"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
import json
import time
from dataclasses import dataclass
from os import getenv
from typing import Tuple, Mapping, Optional, List, Any, Dict, Type
from uuid import uuid4

from acapy_controller import Controller
from acapy_controller.controller import Minimal, MinType
from acapy_controller.logging import logging_to_stdout
from acapy_controller.protocols import didexchange
from acapy_controller.models import (
    V20PresExRecord,
)
from typing_extensions import Union

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:3001")


@dataclass
class V20CredExRecord(Minimal):
    """V2.0 credential exchange record."""

    state: str
    cred_ex_id: str
    connection_id: str
    thread_id: str


@dataclass
class V20CredExRecordFormat(Minimal):
    """V2.0 credential exchange record anoncreds."""

    rev_reg_id: Optional[str] = None
    cred_rev_id: Optional[str] = None


@dataclass
class V20CredExRecordDetail(Minimal):
    """V2.0 credential exchange record detail."""

    cred_ex_record: V20CredExRecord
    details: Optional[V20CredExRecordFormat] = None


@dataclass
class CredInfo(Minimal):
    """Credential information."""

    referent: str
    attrs: Dict[str, Any]


@dataclass
class CredPrecis(Minimal):
    """Credential precis."""

    cred_info: CredInfo
    presentation_referents: List[str]

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the credential precis."""
        value = dict(value)
        if cred_info := value.get("cred_info"):
            value["cred_info"] = CredInfo.deserialize(cred_info)
        return super().deserialize(value)


@dataclass
class ProofRequest(Minimal):
    """Proof request."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]


@dataclass
class PresSpec(Minimal):
    """Presentation specification."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]
    self_attested_attributes: Dict[str, Any]


@dataclass
class Settings(Minimal):
    """Settings information."""


def format_json(json_to_format):
    """Pretty print json."""
    return json.dumps(json_to_format, indent=4)


async def create_did(issuer):
    """Create a DID on the Cheqd testnet."""
    did_create_result = await issuer.post("/did/cheqd/create")
    did = did_create_result.get("did")

    assert did, "DID creation failed."
    assert did_create_result.get("verkey"), "Verkey is missing in DID creation result."

    print(f"Created DID: {did}")
    return did


async def resolve_did(issuer, did):
    """Resolve the DID document."""
    resolution_result = await issuer.get(f"/resolver/resolve/{did}")
    did_document = resolution_result.get("did_document")

    assert did_document, "DID document resolution failed."
    print(f"Resolved DID Document: {format_json(did_document)}")
    return did_document


async def update_did(issuer, did, did_document):
    """Update the DID document by adding a service endpoint."""
    service = [
        {
            "id": f"{did}#service-1",
            "type": "MessagingService",
            "serviceEndpoint": ["https://example.com/service"],
        }
    ]
    did_document["service"] = service
    del did_document["@context"]

    did_update_result = await issuer.post(
        "/did/cheqd/update", json={"did": did, "didDocument": did_document}
    )
    updated_did_doc = did_update_result.get("didDocument")
    updated_did = did_update_result.get("did")

    assert updated_did == did, "DID mismatch after update."
    assert (
        "service" in updated_did_doc
    ), "Key 'service' is missing in updated DID document."
    assert (
        updated_did_doc["service"] == service
    ), "Service does not match the expected value!"

    print(f"Updated DID Document: {format_json(updated_did_doc)}")
    return updated_did_doc


async def deactivate_did(issuer, did):
    """Deactivate a DID on the Cheqd testnet."""
    did_deactivate_result = await issuer.post(
        "/did/cheqd/deactivate",
        json={
            "did": did,
            "options": {"network": "testnet"},
        },
    )

    assert did_deactivate_result.get("did") == did, "DID mismatch after deactivation."
    assert (
        did_deactivate_result.get("did_document_metadata", {}).get("deactivated") is True
    ), "DID document metadata does not contain deactivated=true."

    print(f"Deactivated DID: {format_json(did_deactivate_result) }")


async def create_schema(issuer, did):
    """Create a schema on the Cheqd testnet."""
    schema_create_result = await issuer.post(
        "/anoncreds/schema",
        json={
            "schema": {
                "attrNames": ["score"],
                "issuerId": did,
                "name": "Example schema",
                "version": "1.0",
            }
        },
    )
    print(f"Created schema: {format_json(schema_create_result)}")
    schema_state = schema_create_result.get("schema_state")
    assert schema_state.get("state") == "finished", "Schema state is not finished."
    assert "schema_id" in schema_state, "Key 'schema_id' is missing in schema_state."

    schema_id = schema_state.get("schema_id")
    assert (
        did in schema_id
    ), f"schema_id does not contain the expected DID. Expected '{did}' in '{schema_id}'."

    return schema_id


async def create_credential_definition(issuer, did, schema_id):
    """Create a credential definition on the connected datastore."""
    cred_def_create_result = await issuer.post(
        "/anoncreds/credential-definition",
        json={
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": "default",
            },
            "options": {"support_revocation": True},
        },
    )

    cred_def_state = cred_def_create_result.get("credential_definition_state", {})
    assert cred_def_state.get("state") == "finished", "Cred def state is not finished."
    assert (
        "credential_definition_id" in cred_def_state
    ), "Key 'credential_definition_id' is missing in credential_definition_state."

    credential_definition_id = cred_def_state.get("credential_definition_id")
    assert (
        did in credential_definition_id
    ), "credential_definition_id does not contain the expected DID."

    print(f"Created credential definition: {format_json(cred_def_create_result)}")
    return credential_definition_id


async def assert_credential_definitions(issuer, credential_definition_id):
    """Retrieve all cred_defs & ensure array contain created credential_definition_id."""
    get_result = await issuer.get("/anoncreds/credential-definitions")

    credential_definition_ids = get_result.get("credential_definition_ids", [])
    assert (
        credential_definition_id in credential_definition_ids
    ), "credential_definition_ids does not contain the expected credential_definition_id."


async def assert_wallet_dids(issuer, did):
    """Retrieve all wallet dids and ensure array contain created did."""
    get_result = await issuer.get("/wallet/did?method=cheqd")

    dids = get_result.get("results", [])
    assert any(obj.get("did") == did for obj in dids), f"DID {did} not found in array"


async def issue_credential_v2(
    issuer: Controller,
    holder: Controller,
    issuer_connection_id: str,
    holder_connection_id: str,
    cred_def_id: str,
    attributes: Mapping[str, str],
) -> Tuple[V20CredExRecordDetail, V20CredExRecordDetail]:
    """Issue an credential using issue-credential/2.0.

    Issuer and holder should already be connected.
    """

    is_issuer_anoncreds = (await issuer.get("/settings", response=Settings)).get(
        "wallet.type"
    ) == "askar-anoncreds"
    is_holder_anoncreds = (await holder.get("/settings", response=Settings)).get(
        "wallet.type"
    ) == "askar-anoncreds"

    if is_issuer_anoncreds and is_holder_anoncreds:
        _filter = {"anoncreds": {"cred_def_id": cred_def_id}}
    else:
        _filter = {"indy": {"cred_def_id": cred_def_id}}
    issuer_cred_ex = await issuer.post(
        "/issue-credential-2.0/send-offer",
        json={
            "auto_issue": False,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "filter": _filter,
            "credential_preview": {
                "type": "issue-credential-2.0/2.0/credential-preview",  # pyright: ignore
                "attributes": [
                    {
                        "mime_type": None,
                        "name": name,
                        "value": value,
                    }
                    for name, value in attributes.items()
                ],
            },
        },
        response=V20CredExRecord,
    )
    issuer_cred_ex_id = issuer_cred_ex.cred_ex_id

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        connection_id=holder_connection_id,
        state="offer-received",
    )
    holder_cred_ex_id = holder_cred_ex.cred_ex_id

    await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/send-request",
        response=V20CredExRecord,
    )

    await issuer.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=issuer_cred_ex_id,
        state="request-received",
    )

    await issuer.post(
        f"/issue-credential-2.0/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V20CredExRecordDetail,
    )

    await holder.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=holder_cred_ex_id,
        state="credential-received",
    )

    await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/store",
        json={},
        response=V20CredExRecordDetail,
    )
    issuer_cred_ex = await issuer.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=issuer_cred_ex_id,
        state="done",
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=holder_cred_ex_id,
        state="done",
    )

    return (
        V20CredExRecordDetail(cred_ex_record=issuer_cred_ex),
        V20CredExRecordDetail(cred_ex_record=holder_cred_ex),
    )


def auto_select_credentials_for_presentation_request(
    presentation_request: Union[ProofRequest, dict],
    relevant_creds: List[CredPrecis],
) -> PresSpec:
    """Select credentials to use for presentation automatically."""
    if isinstance(presentation_request, dict):
        presentation_request = ProofRequest.deserialize(presentation_request)

    requested_attributes = {}
    for pres_referrent in presentation_request.requested_attributes.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_attributes[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                    "revealed": True,
                }
    requested_predicates = {}
    for pres_referrent in presentation_request.requested_predicates.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_predicates[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                }

    return PresSpec.deserialize(
        {
            "requested_attributes": requested_attributes,
            "requested_predicates": requested_predicates,
            "self_attested_attributes": {},
        }
    )


async def present_proof_v2(
    holder: Controller,
    verifier: Controller,
    holder_connection_id: str,
    verifier_connection_id: str,
    *,
    name: Optional[str] = None,
    version: Optional[str] = None,
    comment: Optional[str] = None,
    requested_attributes: Optional[List[Mapping[str, Any]]] = None,
    requested_predicates: Optional[List[Mapping[str, Any]]] = None,
    non_revoked: Optional[Mapping[str, int]] = None,
):
    """Present a credential using present proof v2."""

    is_verifier_anoncreds = (await verifier.get("/settings", response=Settings)).get(
        "wallet.type"
    ) == "askar-anoncreds"

    attrs = {
        "name": name or "proof",
        "version": version or "0.1.0",
        "requested_attributes": {
            str(uuid4()): attr for attr in requested_attributes or []
        },
        "requested_predicates": {
            str(uuid4()): pred for pred in requested_predicates or []
        },
        "non_revoked": (non_revoked if non_revoked else None),
    }

    if is_verifier_anoncreds:
        presentation_request = {
            "anoncreds": attrs,
        }
    else:
        presentation_request = {
            "indy": attrs,
        }
    verifier_pres_ex = await verifier.post(
        "/present-proof-2.0/send-request",
        json={
            "auto_verify": False,
            "auto_remove": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "presentation_request": presentation_request,
            "trace": False,
        },
        response=V20PresExRecord,
    )
    verifier_pres_ex_id = verifier_pres_ex.pres_ex_id

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        connection_id=holder_connection_id,
        state="request-received",
    )
    assert holder_pres_ex.pres_request
    holder_pres_ex_id = holder_pres_ex.pres_ex_id

    relevant_creds = await holder.get(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/credentials",
        response=List[CredPrecis],
    )
    assert holder_pres_ex.by_format.pres_request
    proof_request = holder_pres_ex.by_format.pres_request.get(
        "anoncreds"
    ) or holder_pres_ex.by_format.pres_request.get("indy")
    pres_spec = auto_select_credentials_for_presentation_request(
        proof_request, relevant_creds
    )
    if is_verifier_anoncreds:
        proof = {"anoncreds": pres_spec.serialize()}
    else:
        proof = {"indy": pres_spec.serialize()}
    await holder.post(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/send-presentation",
        json=proof,
        response=V20PresExRecord,
    )

    await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="presentation-received",
    )
    await verifier.post(
        f"/present-proof-2.0/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V20PresExRecord,
    )
    verifier_pres_ex = await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="done",
    )

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=holder_pres_ex_id,
        state="done",
    )

    return holder_pres_ex, verifier_pres_ex


async def main():
    """Test DID Cheqd workflow."""
    async with Controller(base_url=ISSUER) as issuer, Controller(
        base_url=HOLDER
    ) as holder:
        """
            This section of the test script demonstrates the CRUD operations of a did
            followed by creating schema, credential definition and credential issuance.
        """
        did = await create_did(issuer)

        await resolve_did(issuer, did)

        # updated_did_document = await update_did(issuer, did, did_document)

        schema_id = await create_schema(issuer, did)
        print(schema_id)

        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id
        )
        print(credential_definition_id)

        await assert_credential_definitions(issuer, credential_definition_id)
        await assert_wallet_dids(issuer, did)

        # fetch revocation registry ids
        # rev_reg_ids = await get_revocation_regs(issuer, credential_definition_id)
        # assert(len(rev_reg_ids) == 2)

        # Connect issuer and holder
        issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
            issuer, holder
        )

        # Issue credential
        issuer_cred_ex, _ = await issue_credential_v2(
            issuer,
            holder,
            issuer_conn_with_anoncreds_holder.connection_id,
            holder_anoncreds_conn.connection_id,
            credential_definition_id,
            {"score": "99"},
        )
        print(issuer_cred_ex)

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time())},
        )
        assert verifier_pres_ex.verified

        # Revoke credential
        await issuer.post(
            url="/anoncreds/revocation/revoke",
            json={
                "connection_id": issuer_conn_with_anoncreds_holder.connection_id,
                "rev_reg_id": issuer_cred_ex.details.rev_reg_id,
                "cred_rev_id": issuer_cred_ex.details.cred_rev_id,
                "publish": True,
                "notify": True,
                "notify_version": "v1_0",
            },
        )

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time())},
        )
        assert not verifier_pres_ex.verified

        # await deactivate_did(issuer, did)


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
