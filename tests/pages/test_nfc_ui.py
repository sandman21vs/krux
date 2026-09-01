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


def mock_nfc(mocker, tag=object(), has_record=False, record=ENVELOPE):
    """A stand-in for the NFC facade, with the card stack already exercised"""
    nfc = mocker.MagicMock()
    nfc.poll.return_value = tag
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

    page = NFCTapPage(create_ctx(mocker, []))
    assert not page.open_reader()
    nfc.init.assert_not_called()


def test_missing_reader_is_reported(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.nfc.errors import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.init.side_effect = NFCNotFound("No reader")

    ctx = create_ctx(mocker, [])
    page = NFCTapPage(ctx)
    assert not page.open_reader()
    assert page.nfc is None


def test_reader_probe_leaves_nothing_attached(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.pages import MENU_CONTINUE

    nfc = mock_nfc(mocker)

    page = NFCTapPage(create_ctx(mocker, []))
    assert page.test_reader() == MENU_CONTINUE
    nfc.init.assert_called_once()
    nfc.deinit.assert_called_once()
    # A probe never energizes the antenna
    nfc.field.assert_not_called()


# ---------- Tap page ----------


def test_cancelling_the_tap_page_drops_the_field(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.input import BUTTON_PAGE
    from krux.nfc.errors import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = NFCNotFound("No card")

    page = NFCTapPage(create_ctx(mocker, [BUTTON_PAGE]))
    page.open_reader()
    assert page.wait_for_tag("Save to NFC") is None
    nfc.field.assert_any_call(True)
    nfc.field.assert_any_call(False)


def test_a_card_that_shows_up_is_handed_over(nfc_on, mocker):
    from krux.pages.nfc_ui import NFCTapPage
    from krux.nfc.errors import NFCNotFound

    tag = object()
    nfc = mock_nfc(mocker, tag=tag)
    # Empty field twice, then a card
    nfc.poll.side_effect = [NFCNotFound("No card"), NFCNotFound("No card"), tag]

    page = NFCTapPage(create_ctx(mocker, [None, None]))
    page.open_reader()
    assert page.wait_for_tag("Save to NFC") is tag


# ---------- Store ----------


def test_store_writes_the_envelope(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_ENTER

    tag = object()
    nfc = mock_nfc(mocker, tag=tag)

    # One press dismisses the confirmation screen
    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER])).write(ENVELOPE, "abcd1234")
    nfc.write_record.assert_called_once_with(tag, ENVELOPE)
    nfc.deinit.assert_called_once()


def test_store_asks_before_overwriting(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_ENTER

    tag = object()
    nfc = mock_nfc(mocker, tag=tag, has_record=True)

    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER, BUTTON_ENTER])).write(
        ENVELOPE, "abcd1234"
    )
    nfc.write_record.assert_called_once_with(tag, ENVELOPE)


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
    from krux.nfc.errors import InvalidRecordError

    nfc = mock_nfc(mocker)
    nfc.write_record.side_effect = InvalidRecordError("too big")

    ctx = create_ctx(mocker, [])
    StoreOnNFC(ctx).write(ENVELOPE, "abcd1234")
    ctx.display.flash_text.assert_called_once()
    nfc.deinit.assert_called_once()


# ---------- Load ----------


def test_load_returns_the_envelope_and_drops_the_reader(nfc_on, mocker):
    from krux.pages.nfc_ui import LoadFromNFC

    nfc = mock_nfc(mocker)

    page = LoadFromNFC(create_ctx(mocker, []))
    assert page.read() == ENVELOPE
    # The password prompt only ever runs with the antenna already down
    nfc.deinit.assert_called_once()


def test_load_from_a_card_with_no_backup(nfc_on, mocker):
    from krux.pages.nfc_ui import LoadFromNFC
    from krux.nfc.errors import NoRecordError

    nfc = mock_nfc(mocker)
    nfc.read_record.side_effect = NoRecordError("no record")

    ctx = create_ctx(mocker, [])
    assert LoadFromNFC(ctx).read() is None
    nfc.deinit.assert_called_once()


def test_load_decrypts_into_words(nfc_on, mocker):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=True)
    mocker.patch.object(KEFEnvelope, "unseal_ui", return_value=ENTROPY_12)

    words = LoadEncryptedMnemonic(create_ctx(mocker, [])).load_from_nfc()
    assert len(words) == 12


def test_load_refuses_a_payload_that_is_not_entropy(nfc_on, mocker):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope
    from krux.pages import MENU_CONTINUE

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=True)
    # A card that decrypts to plaintext words - a format Krux never writes to
    # one, and therefore one no genuine card can present
    mocker.patch.object(
        KEFEnvelope, "unseal_ui", return_value=b"abandon abandon abandon"
    )

    ctx = create_ctx(mocker, [])
    assert LoadEncryptedMnemonic(ctx).load_from_nfc() == MENU_CONTINUE
    ctx.display.flash_text.assert_called_once()


def test_load_refuses_data_that_is_not_a_kef_envelope(nfc_on, mocker):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope
    from krux.pages import MENU_CONTINUE

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=False)

    ctx = create_ctx(mocker, [])
    assert LoadEncryptedMnemonic(ctx).load_from_nfc() == MENU_CONTINUE
    ctx.display.flash_text.assert_called_once()


def test_load_reports_a_wrong_password(nfc_on, mocker):
    from krux.pages.encryption_ui import LoadEncryptedMnemonic, KEFEnvelope
    from krux.pages import MENU_CONTINUE

    mock_nfc(mocker)
    mocker.patch.object(KEFEnvelope, "parse", return_value=True)
    mocker.patch.object(
        KEFEnvelope, "unseal_ui", side_effect=KeyError("Failed to decrypt")
    )

    ctx = create_ctx(mocker, [])
    assert LoadEncryptedMnemonic(ctx).load_from_nfc() == MENU_CONTINUE
    ctx.display.flash_text.assert_called_once()


# ---------- Erase ----------


def test_erase_blanks_a_card_that_holds_a_backup(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFCCard
    from krux.input import BUTTON_ENTER

    tag = object()
    nfc = mock_nfc(mocker, tag=tag, has_record=True)

    EraseNFCCard(create_ctx(mocker, [BUTTON_ENTER])).erase()
    nfc.erase.assert_called_once_with(tag)


def test_erase_leaves_a_card_without_a_backup_alone(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFCCard

    nfc = mock_nfc(mocker, has_record=False)

    EraseNFCCard(create_ctx(mocker, [])).erase()
    nfc.erase.assert_not_called()


def test_erase_can_be_declined(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFCCard
    from krux.input import BUTTON_PAGE

    nfc = mock_nfc(mocker, has_record=True)

    EraseNFCCard(create_ctx(mocker, [BUTTON_PAGE])).erase()
    nfc.erase.assert_not_called()


# ---------- Menu gating ----------


def _load_menu_labels(mocker):
    """The labels 'Load Mnemonic' offers, without running its loop"""
    from krux.pages.login import Login
    import krux.pages.mnemonic_loader as loader

    captured = []

    class FakeMenu:
        """Captures the items instead of drawing them"""

        back_index = 0

        def __init__(self, _ctx, items, **_kwargs):
            captured.extend(items)

        def run_loop(self, *_args, **_kwargs):
            return 0, None

    mocker.patch.object(loader, "Menu", FakeMenu)
    Login(create_ctx(mocker, [])).load_key()
    return [item[0] for item in captured]


def test_load_menu_hides_nfc_while_it_is_off(m5stickv, mocker):
    from krux.krux_settings import Settings

    Settings().hardware.nfc.enabled = False
    labels = _load_menu_labels(mocker)
    assert "From Storage" in labels
    assert not any("NFC" in label for label in labels)


def test_load_menu_offers_nfc_when_it_is_on(nfc_on, mocker):
    assert "From NFC Card" in _load_menu_labels(mocker)


def test_backup_menu_offers_nfc_when_it_is_on(nfc_on, mocker):
    import krux.pages.encryption_ui as encryption_ui

    captured = []

    class FakeMenu:
        """Captures the items instead of drawing them"""

        def __init__(self, _ctx, items, **_kwargs):
            captured.extend(items)

        def run_loop(self, *_args, **_kwargs):
            return 0, None

    mocker.patch.object(encryption_ui, "Menu", FakeMenu)
    encryption_ui.EncryptMnemonic(create_ctx(mocker, [])).encrypt_menu()
    labels = [item[0] for item in captured]
    assert "Store on NFC Card" in labels
    assert labels.index("Store on NFC Card") == 2
