"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
from os import getenv

from acapy_controller import Controller
from acapy_controller.logging import logging_to_stdout
from acapy_controller.protocols import didexchange
from helpers import (
    assert_credential_definitions,
    assert_wallet_dids,
    create_credential_definition,
    create_did,
    create_schema,
    deactivate_did,
    issue_credential_v2,
    resolve_did,
)

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:3001")


async def scenario1_create_and_resolve_did(issuer):
    """Perform a scenario involving DID creation and resolution.

    This function demonstrates the creation of a DID using the provided issuer
    controller, followed by resolving the created DID to retrieve its document.
    """
    did = await create_did(issuer)

    await resolve_did(issuer, did)

    # updated_did_document = await update_did(issuer, did, did_document)

    return did


async def scenario2_create_schema_and_credential_definition(issuer, did):
    """Perform a scenario involving schema and credential definition creation.

    This function demonstrates the creation of a schema and a corresponding credential
    definition using the provided issuer controller and DID. It also validates the
    created credential definition and asserts the presence of the DID in the wallet.
    """
    schema_id = await create_schema(issuer, did)
    print(schema_id)

    credential_definition_id = await create_credential_definition(issuer, did, schema_id)
    print(credential_definition_id)

    await assert_credential_definitions(issuer, credential_definition_id)
    await assert_wallet_dids(issuer, did)

    return credential_definition_id


async def scenario3_issue_credential(issuer, holder, credential_definition_id):
    """Perform a scenario involving credential issuance.

    This function demonstrates the process of connecting an issuer and holder,
    followed by issuing a credential based on a given credential definition ID.
    It uses DID exchange for establishing connections and then issues the credential
    with specified attributes.
    """
    # Connect issuer and holder
    issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
        issuer, holder
    )

    issue_credential_result = await issue_credential_v2(
        issuer,
        holder,
        issuer_conn_with_anoncreds_holder.connection_id,
        holder_anoncreds_conn.connection_id,
        credential_definition_id,
        {"score": "99"},
    )
    print(issue_credential_result)


async def scenario4_deactivate_did(issuer, did):
    """Perform a scenario to deactivate a DID.

    This function demonstrates the deactivation of a given DID using the provided
    issuer controller.
    """
    await deactivate_did(issuer, did)


async def main():
    """Test DID Cheqd workflow."""
    async with Controller(base_url=ISSUER) as issuer, Controller(
        base_url=HOLDER
    ) as holder:
        """
            This section of the test script demonstrates the CRUD operations of a did
            followed by creating schema, credential definition and credential issuance.
        """
        did = await scenario1_create_and_resolve_did(issuer)

        credential_definition_id = (
            await scenario2_create_schema_and_credential_definition(issuer, did)
        )

        await scenario3_issue_credential(issuer, holder, credential_definition_id)

        # await scenario4_deactivate_did(issuer, did)


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
