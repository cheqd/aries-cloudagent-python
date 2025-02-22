import json
from unittest import IsolatedAsyncioTestCase

import pytest

from .....admin.request_context import AdminRequestContext
from .....connections.models.conn_record import ConnRecord
from .....ledger.base import BaseLedger
from .....tests import mock
from .....utils.testing import create_test_profile
from .....wallet.base import BaseWallet
from .....wallet.did_info import DIDInfo
from .....wallet.did_method import SOV
from .....wallet.key_type import ED25519
from .. import routes as test_module
from ..models.transaction_record import TransactionRecord

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:tag1"


class TestEndorseTransactionRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "secret-key",
            }
        )
        self.context = AdminRequestContext.test_context({}, self.profile)

        self.ledger = mock.MagicMock(BaseLedger, autospec=True)
        self.ledger.txn_submit = mock.CoroutineMock(
            return_value=json.dumps(
                {
                    "result": {
                        "txn": {"type": "101", "metadata": {"from": TEST_DID}},
                        "txnMetadata": {"txnId": SCHEMA_ID},
                    }
                }
            )
        )
        self.ledger.get_schema = mock.CoroutineMock(
            return_value={"id": SCHEMA_ID, "...": "..."}
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        self.request_dict = {
            "context": self.context,
            "outbound_message_router": mock.CoroutineMock(),
        }
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

        self.test_did = "sample-did"

    async def test_transactions_list(self):
        with (
            mock.patch.object(
                TransactionRecord, "query", mock.CoroutineMock()
            ) as mock_query,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_query.return_value = [
                mock.MagicMock(serialize=mock.MagicMock(return_value={"...": "..."}))
            ]
            await test_module.transactions_list(self.request)

            mock_response.assert_called_once_with({"results": [{"...": "..."}]})

    async def test_transactions_list_x(self):
        with (
            mock.patch.object(
                TransactionRecord, "query", mock.CoroutineMock()
            ) as mock_query,
            mock.patch.object(test_module.web, "json_response"),
        ):
            mock_query.side_effect = test_module.StorageError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transactions_list(self.request)

    async def test_transactions_retrieve(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_retrieve,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transactions_retrieve(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_transactions_retrieve_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_retrieve:
            mock_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transactions_retrieve(self.request)

    async def test_transactions_retrieve_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_retrieve:
            mock_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transactions_retrieve(self.request)

    async def test_transaction_create_request(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_request=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transaction_create_request(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_transaction_create_request_not_found_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_base_model_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_jobs_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_request=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_my_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_request=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_their_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_request=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_my_wrong_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_mgr_create_request_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_request=mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_create_request(self.request)

    async def test_endorse_transaction_response(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_endorse_response=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.endorse_transaction_response(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    # TODO code re-factored from routes.py to manager.py so tests must be moved
    @pytest.mark.skip("Need to fix")
    async def test_endorse_transaction_response_no_wallet_x(self):
        self.session.context.injector.clear_binding(BaseWallet)
        with self.assertRaises(test_module.web.HTTPForbidden):
            await test_module.endorse_transaction_response(self.request)

    @pytest.mark.skip("Need to fix")
    async def test_endorse_transaction_response_no_endorser_did_info_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.session.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(get_public_did=mock.CoroutineMock(return_value=None)),
        )
        with mock.patch.object(
            self.context.profile,
            "session",
            mock.MagicMock(return_value=self.session),
        ):
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    @pytest.mark.skip("Need to fix")
    async def test_endorse_transaction_response_no_ledger_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.context.injector.clear_binding(BaseLedger)
        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_endorse_response=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    @pytest.mark.skip("Need to fix")
    async def test_endorse_transaction_response_ledger_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )
        self.ledger.txn_endorse = mock.CoroutineMock(
            side_effect=test_module.LedgerError()
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_endorse_response=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(
                            serialize=mock.MagicMock(return_value={"...": "..."})
                        ),
                        mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response"),
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_endorse_response=mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_refuse_transaction_response(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_refuse_response=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=mock.MagicMock(return_value={"...": "..."}),
                        ),
                        mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.refuse_transaction_response(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_refuse_transaction_response_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_conn_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseWallet,
            mock.MagicMock(
                get_public_did=mock.CoroutineMock(
                    return_value=DIDInfo(
                        "did",
                        "verkey",
                        {"meta": "data"},
                        method=SOV,
                        key_type=ED25519,
                    )
                )
            ),
        )

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response"),
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                create_refuse_response=mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.refuse_transaction_response(self.request)

    async def test_cancel_transaction(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                cancel_transaction=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=mock.MagicMock(return_value={"...": "..."}),
                        ),
                        mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.cancel_transaction(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_cancel_transaction_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_conn_rec_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response"),
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                cancel_transaction=mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.cancel_transaction(self.request)

    async def test_transaction_resend(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                transaction_resend=mock.CoroutineMock(
                    return_value=(
                        mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=mock.MagicMock(return_value={"...": "..."}),
                        ),
                        mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transaction_resend(self.request)

        mock_response.assert_called_once_with({"...": "..."})

    async def test_transaction_resend_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_conn_rec_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_my_wrong_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response"),
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                transaction_resend=mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_resend(self.request)

    async def test_set_endorser_role(self):
        self.request.match_info = {"conn_id": "dummy"}

        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                set_transaction_my_job=mock.CoroutineMock()
            )
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            await test_module.set_endorser_role(self.request)

        mock_response.assert_called_once_with(
            {"transaction_my_job": test_module.TransactionJob.TRANSACTION_AUTHOR.name}
        )

    async def test_set_endorser_role_not_found_x(self):
        self.request.match_info = {"conn_id": "dummy"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.set_endorser_role(self.request)

    async def test_set_endorser_role_base_model_x(self):
        self.request.match_info = {"conn_id": "dummy"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.set_endorser_role(self.request)

    async def test_set_endorser_info(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                ),
                metadata_set=mock.CoroutineMock(),
            )
            await test_module.set_endorser_info(self.request)

            mock_response.assert_called_once_with(
                {
                    "transaction_my_job": "TRANSACTION_AUTHOR",
                    "transaction_their_job": "TRANSACTION_ENDORSER",
                    "endorser_did": "did",
                    "endorser_name": "name",
                }
            )

    async def test_set_endorser_info_no_prior_value(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with (
            mock.patch.object(
                ConnRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_conn_rec_retrieve,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    side_effect=[
                        {
                            "transaction_my_job": (
                                test_module.TransactionJob.TRANSACTION_AUTHOR.name
                            ),
                            "transaction_their_job": (
                                test_module.TransactionJob.TRANSACTION_ENDORSER.name
                            ),
                        },
                        None,
                        {
                            "endorser_did": "did",
                            "endorser_name": "name",
                        },
                    ]
                ),
                metadata_set=mock.CoroutineMock(),
            )
            await test_module.set_endorser_info(self.request)

            mock_response.assert_called_once_with(
                {
                    "endorser_did": "did",
                    "endorser_name": "name",
                }
            )

    async def test_set_endorser_info_not_found_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_base_model_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_no_transaction_jobs_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(return_value=None)
            )
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_no_transaction_my_job_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_my_wrong_job_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with mock.patch.object(
            ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = mock.MagicMock(
                metadata_get=mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    async def test_transaction_write_schema_txn(self):
        self.request.match_info = {"tran_id": "dummy"}
        with (
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_txn_mgr.return_value.complete_transaction = mock.CoroutineMock()

            mock_txn_mgr.return_value.complete_transaction.return_value = (
                mock.CoroutineMock(serialize=mock.MagicMock(return_value={"...": "..."})),
                mock.CoroutineMock(),
            )

            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[{"data": {"json": json.dumps({"message": "attached"})}}],
            )
            await test_module.transaction_write(self.request)
            mock_response.assert_called_once_with({"...": "..."})

    async def test_transaction_write_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_wrong_state_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        with mock.patch.object(
            TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_CREATED,
                messages_attach=[{"data": {"json": json.dumps({"message": "attached"})}}],
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_schema_txn_complete_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        with (
            mock.patch.object(
                TransactionRecord, "retrieve_by_id", mock.CoroutineMock()
            ) as mock_txn_rec_retrieve,
            mock.patch.object(
                test_module, "TransactionManager", mock.MagicMock()
            ) as mock_txn_mgr,
        ):
            mock_txn_mgr.return_value = mock.MagicMock(
                complete_transaction=mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )

            mock_txn_rec_retrieve.return_value = mock.MagicMock(
                serialize=mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[{"data": {"json": json.dumps({"message": "attached"})}}],
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)

    async def test_register(self):
        mock_app = mock.MagicMock()
        mock_app.add_routes = mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = mock.MagicMock(_state={"swagger_dict": {"paths": {}}})
        test_module.post_process_routes(mock_app)

        assert "tags" in mock_app._state["swagger_dict"]
