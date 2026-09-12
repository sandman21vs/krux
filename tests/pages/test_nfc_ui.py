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
    from krux.nfc import RECORD_KEF

    nfc = mock_nfc(mocker)
    # One press dismisses the confirmation screen
    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER])).write(ENVELOPE, "abcd1234")

    nfc.write_record.assert_called_once_with(ENVELOPE, RECORD_KEF)
    nfc.deinit.assert_called_once()


def test_store_asks_before_overwriting(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_ENTER
    from krux.nfc import RECORD_KEF

    nfc = mock_nfc(mocker, has_record=True)
    StoreOnNFC(create_ctx(mocker, [BUTTON_ENTER, BUTTON_ENTER])).write(
        ENVELOPE, "abcd1234"
    )
    nfc.write_record.assert_called_once_with(ENVELOPE, RECORD_KEF)


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


def test_store_descriptor_tags_the_record_as_a_descriptor(nfc_on, mocker):
    """The type byte is what keeps this card out of the mnemonic loader"""
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.nfc import RECORD_DESCRIPTOR

    nfc = mock_nfc(mocker)
    StoreOnNFC(create_ctx(mocker, [])).write_descriptor(ENVELOPE)

    nfc.write_record.assert_called_once_with(ENVELOPE, RECORD_DESCRIPTOR)
    nfc.field.assert_any_call(True)
    nfc.deinit.assert_called_once()


def test_store_descriptor_reports_a_card_that_cannot_hold_it(nfc_on, mocker):
    """A 3 of 5 is several times the size of a seed, so this path is reachable"""
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.nfc import NFCSizeError

    nfc = mock_nfc(mocker)
    nfc.write_record.side_effect = NFCSizeError("too big")

    ctx = create_ctx(mocker, [])
    StoreOnNFC(ctx).write_descriptor(ENVELOPE)
    ctx.display.flash_text.assert_called_once()
    nfc.deinit.assert_called_once()


def test_store_descriptor_warns_before_replacing_a_seed(nfc_on, mocker):
    """has_record() takes no type, so the card holding a seed still warns"""
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_PAGE

    nfc = mock_nfc(mocker, has_record=True)
    # BUTTON_PAGE answers "No" on a minimal display
    StoreOnNFC(create_ctx(mocker, [BUTTON_PAGE])).write_descriptor(ENVELOPE)

    nfc.write_record.assert_not_called()
    nfc.deinit.assert_called_once()


def test_a_write_that_fails_mid_card_is_reported(nfc_on, mocker):
    """Not a size problem - the card moved, or a block refused the write"""
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.nfc import NFCError

    for store in ("write", "write_descriptor"):
        nfc = mock_nfc(mocker)
        nfc.write_record.side_effect = NFCError("write not acknowledged")

        ctx = create_ctx(mocker, [])
        page = StoreOnNFC(ctx)
        if store == "write":
            page.write(ENVELOPE, "abcd1234")
        else:
            page.write_descriptor(ENVELOPE)

        ctx.display.flash_text.assert_called_once()
        nfc.deinit.assert_called_once()


def test_leaving_the_tap_page_stores_nothing(nfc_on, mocker):
    from krux.pages.nfc_ui import StoreOnNFC
    from krux.input import BUTTON_PAGE
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = NFCNotFound("No card")

    StoreOnNFC(create_ctx(mocker, [BUTTON_PAGE])).write_descriptor(ENVELOPE)

    nfc.write_record.assert_not_called()
    nfc.field.assert_any_call(False)
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


def test_load_asks_the_card_for_the_type_the_caller_can_parse(nfc_on, mocker):
    from krux.pages.nfc_ui import LoadFromNFC
    from krux.nfc import RECORD_DESCRIPTOR, RECORD_KEF

    nfc = mock_nfc(mocker)
    LoadFromNFC(create_ctx(mocker, [])).read(RECORD_DESCRIPTOR)
    nfc.read_record.assert_called_once_with(RECORD_DESCRIPTOR)

    nfc = mock_nfc(mocker)
    LoadFromNFC(create_ctx(mocker, [])).read()
    nfc.read_record.assert_called_once_with(RECORD_KEF)


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


# ---------- Erase ----------


def test_erase_wipes_the_card(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFC
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker, has_record=True)
    EraseNFC(create_ctx(mocker, [BUTTON_ENTER])).erase()

    nfc.erase.assert_called_once_with()
    nfc.field.assert_any_call(True)
    nfc.deinit.assert_called_once()


def test_erase_asks_first(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFC
    from krux.input import BUTTON_PAGE

    nfc = mock_nfc(mocker, has_record=True)
    # BUTTON_PAGE answers "No" on a minimal display
    EraseNFC(create_ctx(mocker, [BUTTON_PAGE])).erase()

    nfc.erase.assert_not_called()
    nfc.deinit.assert_called_once()


def test_erase_does_not_probe_for_a_record_first(nfc_on, mocker):
    """It takes the whole data area, so what Krux recognises is beside the
    point and reporting it would reassure the wrong way."""
    from krux.pages.nfc_ui import EraseNFC
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker)
    EraseNFC(create_ctx(mocker, [BUTTON_ENTER])).erase()

    nfc.has_record.assert_not_called()
    nfc.erase.assert_called_once_with()


def test_a_card_pulled_away_mid_erase_is_reported(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFC
    from krux.nfc import NFCError
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker)
    nfc.erase.side_effect = NFCError("write not acknowledged")

    ctx = create_ctx(mocker, [BUTTON_ENTER])
    EraseNFC(ctx).erase()

    ctx.display.flash_text.assert_called_once()
    nfc.deinit.assert_called_once()


def test_leaving_the_erase_tap_page_wipes_nothing(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFC
    from krux.input import BUTTON_PAGE
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = NFCNotFound("No card")

    EraseNFC(create_ctx(mocker, [BUTTON_PAGE])).erase()

    nfc.erase.assert_not_called()
    nfc.field.assert_any_call(False)
    nfc.deinit.assert_called_once()


def test_a_card_that_drifts_off_after_the_prompt_is_not_erased(nfc_on, mocker):
    """The confirmation screen was up in between, and the card only had to move
    a centimetre. It is asked for again rather than trusted."""
    from krux.pages.nfc_ui import EraseNFC
    from krux.nfc import NFCNotFound
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    nfc = mock_nfc(mocker)
    nfc.poll.side_effect = [None] + [NFCNotFound("gone")] * 10

    EraseNFC(create_ctx(mocker, [BUTTON_ENTER, BUTTON_PAGE])).erase()

    nfc.erase.assert_not_called()
    nfc.deinit.assert_called_once()


def test_erase_without_a_reader_touches_nothing(nfc_on, mocker):
    from krux.pages.nfc_ui import EraseNFC
    from krux.nfc import NFCNotFound

    nfc = mock_nfc(mocker)
    nfc.init.side_effect = NFCNotFound("No reader")

    EraseNFC(create_ctx(mocker, [])).erase()

    nfc.field.assert_not_called()
    nfc.erase.assert_not_called()


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


def _tools_menu(mocker):
    import krux.pages.tools as tools

    captured = []

    class FakeMenu:
        back_index = 0

        def __init__(self, _ctx, items, **_kwargs):
            captured.extend(items)

        def run_loop(self, *_args, **_kwargs):
            return 0, None

    mocker.patch.object(tools, "Menu", FakeMenu)
    tools.Tools(create_ctx(mocker, []))
    return [item[0] for item in captured]


def test_tools_hides_the_erase_tool_while_nfc_is_off(m5stickv, mocker):
    from krux.krux_settings import Settings

    Settings().hardware.nfc.enabled = False
    labels = _tools_menu(mocker)
    assert "Descriptor Addresses" in labels
    assert not any("NFC" in label for label in labels)


def test_tools_offers_the_erase_tool_when_nfc_is_on(nfc_on, mocker):
    assert "Erase NFC Card" in _tools_menu(mocker)


def test_the_tools_entry_reaches_the_erase_page(nfc_on, mocker):
    from krux.pages.tools import Tools
    from krux.input import BUTTON_ENTER

    nfc = mock_nfc(mocker)
    Tools(create_ctx(mocker, [BUTTON_ENTER])).erase_nfc_card()

    nfc.erase.assert_called_once_with()
