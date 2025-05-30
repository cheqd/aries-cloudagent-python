from unittest import IsolatedAsyncioTestCase

from ......core.oob_processor import OobMessageProcessor
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......tests import mock
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...messages.cred_request import V20CredRequest
from ...models.cred_ex_record import V20CredExRecord
from .. import cred_request_handler as test_module

CD_ID = "LjgpST2rjsoxYegQDRm7EL:3:CL:18:tag"


class TestV20CredRequestHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=mock.MagicMock()
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = False
            request_context.message = V20CredRequest()
            request_context.connection_ready = True
            handler = test_module.V20CredRequestHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.connection_record, oob_record
        )
        assert not responder.messages

    async def test_called_auto_issue(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        cred_ex_rec = V20CredExRecord()

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.CoroutineMock(
                return_value=(None, "cred_issue_message")
            )
            request_context.message = V20CredRequest()
            request_context.connection_ready = True
            handler = test_module.V20CredRequestHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)
            mock_cred_mgr.return_value.issue_credential.assert_called_once_with(
                cred_ex_record=cred_ex_rec, comment=None
            )

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.connection_record, oob_record
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "cred_issue_message"
        assert target == {}

    async def test_called_auto_issue_x_indy(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        cred_ex_rec = V20CredExRecord()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with (
            mock.patch.object(
                test_module, "V20CredManager", autospec=True
            ) as mock_cred_mgr,
            mock.patch.object(cred_ex_rec, "save_error_state", mock.CoroutineMock()),
        ):
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.CoroutineMock(
                side_effect=test_module.IndyIssuerError()
            )

            request_context.message = V20CredRequest()
            request_context.connection_ready = True
            handler = test_module.V20CredRequestHandler()
            responder = MockResponder()

            with (
                mock.patch.object(
                    responder, "send_reply", mock.CoroutineMock()
                ) as mock_send_reply,
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_auto_issue_x_anoncreds(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        cred_ex_rec = V20CredExRecord()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with (
            mock.patch.object(
                test_module, "V20CredManager", autospec=True
            ) as mock_cred_mgr,
            mock.patch.object(cred_ex_rec, "save_error_state", mock.CoroutineMock()),
        ):
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.AsyncMock(
                side_effect=test_module.AnonCredsIssuerError()
            )

            request_context.message = V20CredRequest()
            request_context.connection_ready = True
            handler = test_module.V20CredRequestHandler()
            responder = MockResponder()

            with (
                mock.patch.object(
                    responder, "send_reply", mock.CoroutineMock()
                ) as mock_send_reply,
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock()
            request_context.message = V20CredRequest()
            request_context.connection_ready = False
            handler = test_module.V20CredRequestHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message
                == "Connection used for credential request not ready"
            )

        assert not responder.messages

    async def test_called_no_connection_no_oob(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=None
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        request_context.message = V20CredRequest()
        handler = test_module.V20CredRequestHandler()
        responder = MockResponder()
        with self.assertRaises(test_module.HandlerException) as err:
            await handler.handle(request_context, responder)

        assert not responder.messages
