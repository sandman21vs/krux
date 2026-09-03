# NFC page tests
#
# The card stack itself is covered in tests/test_nfc.py; these are about the
# pages around it - that the reader is never touched while the feature is off,
# that the field comes down on every exit path, and that a card carrying
# something other than a Krux backup cannot walk a seed onto the device.

import pytest
from . import create_ctx

ENVELOPE = b"KEF-ENVELOPE-BYTES"
ENTROPY_12 = bytes(range(16))


@pytest.fixture
def nfc_on(m5stickv):
    """NFC switched on in settings, as the menus require"""
    from krux.krux_settings import Settings

    Settings().hardware.nfc.enabled = True
    yield m5stickv
    Settings().hardware.nfc.enabled = False


def mock_nfc(mocker, has_record=False, record=ENVELOPE):
    """A stand-in for the NFC facade, with the card stack already exercised"""
    nfc = mocker.MagicMock()
    nfc.has_record.return_value = has_record
    nfc.read_record.return_value = record
    mocker.patch("krux.nfc.NFC", mocker.MagicMock(return_value=nfc))
    return nfc


# ---------- The setting is the hardware boundary ----------


def test_disabled_nfc_never_touches_the_bus(m5stickv, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.krux_settings import Settings

    Settings().hardware.nfc.enabled = False
    nfc = mock_nfc(mocker)

    assert not NFCTapPage(create_ctx(mocker, [])).open_reader()
    nfc.init.assert_not_called()


def test_missing_reader_is_reported(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.init.side_effect = NFCNotFound("No reader")

    page = NFCTapPage(create_ctx(mocker, []))
    assert not page.open_reader()
    assert page.nfc is None


def test_reader_probe_leaves_nothing_attached(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage

    nfc = mock_nfc(mocker)
    NFCTapPage(create_ctx(mocker, [])).test_reader()

    nfc.init.assert_called_once()
    nfc.deinit.assert_called_once()
    nfc.field.assert_not_called()  # a probe never energizes the antenna


# ---------- Tap page ----------


def test_cancelling_the_tap_page_drops_the_field(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.input import BUTTON_PAGE
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = NFCNotFound("No card")

    page = NFCTapPage(create_ctx(mocker, [BUTTON_PAGE]))
    page.open_reader()
    assert not page.wait_for_tag("Store on NFC Card")
    nfc.field.assert_any_call(True)
    nfc.field.assert_any_call(False)


def test_polling_continues_until_a_card_shows_up(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = [NFCNotFound("No card"), NFCNotFound("No card"), None]

    page = NFCTapPage(create_ctx(mocker, [None, None]))
    page.open_reader()
    assert page.wait_for_tag("Store on NFC Card")


# ---------- Store ----------


def test_store_writes_the_envelope(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker)
    # One press dismisses the confirmation screen
    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER])).write(ENVELOPE, "abcd1234")

    nfc.write_record.assert_called_once_with(ENVELOPE)
    nfc.deinit.assert_called_once()


def test_store_asks_before_overwriting(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker, has_record=True)
    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER, BUTTON_ENTER])).write(
        ENVELOPE, "abcd1234"
    )
    nfc.write_record.assert_called_once_with(ENVELOPE)


def test_store_declining_the_overwrite_leaves_the_card_alone(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_PAGE

    nfc = mock_nfc(mocker, has_record=True)
    # BUTTON_PAGE answers "No" on a minimal display
    StoreOnNFC(create_ctx(mocker, [BUTTON_PAGE])).write(ENVELOPE, "abcd1234")

    nfc.write_record.assert_not_called()
    nfc.deinit.assert_called_once()


def test_store_reports_a_card_that_cannot_hold_the_backup(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.nfc import NFCSizeError

    nfc = mock_nfc(mocker)
    nfc.write_record.side_effect = NFCSizeError("too big")

    ctx = create_ctx(mocker, [])
    StoreOnNFC(ctx).write(ENVELOPE, "abcd1234")
    ctx.display.flash_text.assert_called_once()
    nfc.deinit.assert_called_once()


# ---------- Load ----------


def test_load_returns_the_envelope_and_drops_the_reader(nfc_on, mocker):
    from krux.pages.nfc_ui import LoadFromNFC

    nfc = mock_nfc(mocker)
    assert LoadFromNFC(create_ctx(mocker, [])).read() == ENVELOPE
    # The password prompt only ever runs with the antenna already down
    nfc.deinit.assert_called_once()


def test_load_from_a_card_with_no_backup(nfc_on, mocker):
    from krux.pages.nfc_ui import LoadFromNFC
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.read_record.side_effect = NFCNotFound("no record")

    assert LoadFromNFC(create_ctx(mocker, [])).read() is None
    nfc.deinit.assert_called_once()


def test_load_decrypts_into_words(nfc_on, mocker):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=True)
    mocker.patch.object(KEFEnvelope, "unseal_ui", return_value=ENTROPY_12)

    assert len(LoadEncryptedMnemonic(create_ctx(mocker, [])).load_from_nfc()) == 12


@pytest.mark.parametrize(
    "parse_ok, unseal",
    [
        # A card that decrypts to plaintext words - a format Krux never writes
        # to one, and therefore one no genuine card can present
        (True, b"abandon abandon abandon"),
        (True, KeyError("Failed to decrypt")),  # wrong password
        (False, None),  # not a KEF envelope at all
    ],
)
def test_a_card_that_is_not_a_krux_backup_loads_nothing(
    nfc_on, mocker, parse_ok, unseal
):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope
    from krux.pages import MENU_CONTINUE

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=parse_ok)
    if isinstance(unseal, Exception):
        mocker.patch.object(KEFEnvelope, "unseal_ui", side_effect=unseal)
    else:
        mocker.patch.object(KEFEnvelope, "unseal_ui", return_value=unseal)

    ctx = create_ctx(mocker, [])
    assert LoadEncryptedMnemonic(ctx).load_from_nfc() == MENU_CONTINUE
    ctx.display.flash_text.assert_called_once()


# ---------- Menu gating ----------


def _menu_labels(mocker, module, run):
    """The labels a menu offers, without running its loop"""
    captured = []

    class FakeMenu:
        back_index = 0

        def __init__(self, _ctx, items, **_kwargs):
            captured.extend(items)

        def run_loop(self, *_args, **_kwargs):
            return 0, None

    mocker.patch.object(module, "Menu", FakeMenu)
    run()
    return [item[0] for item in captured]


def _load_menu(mocker):
    from krux.pages.login import Login
    import krux.pages.mnemonic_loader as loader

    login = Login(create_ctx(mocker, []))
    return _menu_labels(mocker, loader, login.load_key)


def test_load_menu_hides_nfc_while_it_is_off(m5stickv, mocker):
    from krux.krux_settings import Settings

    Settings().hardware.nfc.enabled = False
    labels = _load_menu(mocker)
    assert "From Storage" in labels
    assert not any("NFC" in label for label in labels)


def test_load_menu_offers_nfc_when_it_is_on(nfc_on, mocker):
    assert "From NFC Card" in _load_menu(mocker)


def test_backup_menu_offers_nfc_when_it_is_on(nfc_on, mocker):
    import krux.pages.encryption_ui as encryption_ui

    page = encryption_ui.EncryptMnemonic(create_ctx(mocker, []))
    labels = _menu_labels(mocker, encryption_ui, page.encrypt_menu)
    assert labels.index("Store on NFC Card") == 2
