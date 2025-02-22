"""Test mediate request message handler."""

from unittest import IsolatedAsyncioTestCase

import pytest

from ......connections.models.conn_record import ConnRecord
from ......messaging.base_handler import HandlerException
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......utils.testing import create_test_profile
from ......wallet.did_method import DIDMethods
from ...messages.mediate_grant import MediationGrant
from ...messages.mediate_request import MediationRequest
from ...messages.problem_report import CMProblemReport
from ...models.mediation_record import MediationRecord
from ..mediation_request_handler import MediationRequestHandler

TEST_CONN_ID = "conn-id"
TEST_VERKEY = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"


class TestMediationRequestHandler(IsolatedAsyncioTestCase):
    """Test mediate request message handler."""

    async def asyncSetUp(self):
        """setup dependencies of messaging"""
        self.context = RequestContext.test_context(await create_test_profile())
        self.context.profile.context.injector.bind_instance(DIDMethods, DIDMethods())
        self.session = await self.context.session()
        self.context.message = MediationRequest()
        self.context.connection_ready = True
        self.context.connection_record = ConnRecord(connection_id=TEST_CONN_ID)

    async def test_handler_no_active_connection(self):
        """test mediation handler"""
        handler, responder = MediationRequestHandler(), MockResponder()
        self.context.connection_ready = False
        with pytest.raises(HandlerException):
            await handler.handle(self.context, responder)

    async def test_handler_mediation_record_already_exists(self):
        handler, responder = MediationRequestHandler(), MockResponder()
        await MediationRecord(connection_id=TEST_CONN_ID).save(self.session)
        await handler.handle(self.context, responder)
        messages = responder.messages
        assert len(messages) == 1
        result, _target = messages[0]
        assert isinstance(result, CMProblemReport)

    async def test_handler(self):
        handler, responder = MediationRequestHandler(), MockResponder()
        await handler.handle(self.context, responder)
        record = await MediationRecord.retrieve_by_connection_id(
            self.session, TEST_CONN_ID
        )
        assert record
        assert record.state == MediationRecord.STATE_REQUEST

    async def test_handler_open_mediation(self):
        handler, responder = MediationRequestHandler(), MockResponder()
        self.context.settings.set_value("mediation.open", True)
        await handler.handle(self.context, responder)
        record = await MediationRecord.retrieve_by_connection_id(
            self.session, TEST_CONN_ID
        )
        assert record
        assert record.state == MediationRecord.STATE_GRANTED
        messages = responder.messages
        assert len(messages) == 1
        result, _ = messages[0]
        assert isinstance(result, MediationGrant)
