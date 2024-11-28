"""DID Cheqd Registry."""

import logging
from typing import Optional, Pattern, Sequence
from uuid import uuid4

from aiohttp import web

from ....config.injection_context import InjectionContext
from ....core.profile import Profile
from ...base import (
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
    AnonCredsRegistrationError,
)
from ...models.credential_definition import (
    CredDef,
    CredDefResult,
    GetCredDefResult,
    CredDefState,
    CredDefValue,
)
from ...models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
    RevRegDefValue,
    RevRegDefState,
    RevListState,
)
from ...models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from ....did.cheqd.manager import DidCheqdManager
from ....did.cheqd.registrar import DidCheqdRegistrar
from ....resolver.default.cheqd import CheqdDIDResolver
from ....messaging.valid import CheqdDID
from ....wallet.base import BaseWallet
from ....wallet.jwt import dict_to_b64

LOGGER = logging.getLogger(__name__)


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    registrar: DidCheqdRegistrar
    resolver: CheqdDIDResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self.registrar = DidCheqdRegistrar()
        self.resolver = CheqdDIDResolver()

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return CheqdDID.PATTERN

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema, resource_id: str) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_credential_definition_id(
        credential_definition: CredDef, resource_id: str
    ) -> str:
        """Derive the ID for a credential definition."""
        return f"{credential_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def split_schema_id(schema_id: str) -> (str, str):
        """Derive the ID for a schema."""
        ids = schema_id.split("/")
        return ids[0], ids[2]

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        schema = await self.resolver.resolve_resource(schema_id)
        (did, resource_id) = self.split_schema_id(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=did,
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata={},
            resolution_metadata={
                "resource_id": resource_id,
                "resource_name": schema.get("name"),
                "resource_type": "anonCredsSchema",
            },
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = "anonCredsSchema"
        resource_name = schema.name
        resource_version = schema.version

        LOGGER.debug("Registering schema")
        cheqd_schema = {
            "name": resource_name,
            "type": resource_type,
            "version": resource_version,
            "data": dict_to_b64(
                {
                    "name": schema.name,
                    "version": schema.version,
                    "attrNames": schema.attr_names,
                }
            ),
        }

        LOGGER.debug("schema value: %s", cheqd_schema)
        try:
            resource_state = await self._create_and_publish_resource(
                profile,
                schema.issuer_id,
                cheqd_schema,
            )
            job_id = resource_state.get("jobId")
            resource = resource_state.get("resource")
            resource_id = resource.get("id")
            schema_id = self.make_schema_id(schema, resource_id)
        except Exception as err:
            raise AnonCredsRegistrationError(f"{err}")
        return SchemaResult(
            job_id=job_id,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        credential_definition = await self.resolver.resolve_resource(
            credential_definition_id
        )
        (did, resource_id) = self.split_schema_id(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=did,
            schema_id=credential_definition["schemaId"],
            type=credential_definition["type"],
            tag=credential_definition["tag"],
            value=CredDefValue.deserialize(credential_definition["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata={},
            resolution_metadata={
                "resource_id": resource_id,
                "resource_name": credential_definition.get("tag"),
                "resource_type": "anonCredsCredDef",
            },
        )

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        resource_type = "anonCredsCredDef"
        resource_name = credential_definition.tag

        cred_def = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": credential_definition.value.serialize(),
                    "schemaId": schema.schema_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile, credential_definition.issuer_id, cred_def
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        credential_definition_id = self.make_credential_definition_id(
            credential_definition, resource_id
        )

        return CredDefResult(
            job_id=job_id,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=credential_definition_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            credential_definition_metadata={},
        )

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        revocation_registry_definition = await self.resolver.resolve_resource(
            revocation_registry_id
        )
        (did, resource_id) = self.split_schema_id(revocation_registry_id)

        anoncreds_revocation_registry_definition = RevRegDef(
            issuer_id=did,
            cred_def_id=revocation_registry_definition["cred_def_id"],
            type=revocation_registry_definition["type"],
            tag=revocation_registry_definition["tag"],
            value=RevRegDefValue.deserialize(revocation_registry_definition["value"]),
        )

        return GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata={},
            resolution_metadata={
                "resource_id": resource_id,
                "resource_name": anoncreds_revocation_registry_definition.tag,
                "resource_type": "anonCredsCredDef",
            },
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        did = revocation_registry_definition.issuer_id
        resource_type = "anonCredsRevRegDef"
        rev_reg_def = {
            "name": revocation_registry_definition.tag,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "type": revocation_registry_definition.type,
                    "tag": revocation_registry_definition.tag,
                    "value": revocation_registry_definition.value.serialize(),
                    "credentialDefinitionId": revocation_registry_definition.cred_def_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile, did, rev_reg_def
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")
        resource_name = revocation_registry_definition.tag

        return RevRegDefResult(
            job_id,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=resource_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_registry_definition_metadata={},
        )

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            revocation_registry_id,
        )
        revocation_registry_name = revocation_registry_definition.revocation_registry.tag
        (did, resource_id) = self.split_schema_id(revocation_registry_id)

        resource_type = "anonCredsStatusList"
        status_list = await self.resolver.resolve_resource(
            f"{did}?resourceType={resource_type}&resourceName={revocation_registry_name}&resourceVersionTime=${timestamp_to}"
        )
        revocation_list = RevList(
            issuer_id=did,
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list.get("revocationList"),
            current_accumulator=status_list.get("currentAccumulator"),
            timestamp=timestamp_to,  # fix: return timestamp from resolution metadata
        )

        return GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata={
                "resource_id": resource_id,
                "resource_name": revocation_registry_name,
                "resource_type": resource_type,
            },
            revocation_registry_id=revocation_registry_id,
        )

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        resource_name = rev_reg_def.tag
        resource_type = "anonCredsStatusLit"
        rev_status_list = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "revocationList": rev_list.revocation_list,
                    "currentAccumulator": rev_list.current_accumulator,
                    "revocationRegDefId": rev_list.rev_reg_def_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile, rev_reg_def.issuer_id, rev_status_list
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        return RevListResult(
            job_id,
            revocation_list_state=RevListState.STATE_FINISHED,
            registration_metadata={},
            revocation_list_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        _prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        resource_name = rev_reg_def.tag
        resource_type = "anonCredsStatusLit"
        rev_status_list = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "revocationList": curr_list.revocation_list,
                    "currentAccumulator": curr_list.current_accumulator,
                    "revocationRegDefId": curr_list.rev_reg_def_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile, rev_reg_def.issuer_id, rev_status_list
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        return RevListResult(
            job_id,
            revocation_list_state=RevListState.STATE_FINISHED,
            registration_metadata={},
            revocation_list_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    @staticmethod
    async def _create_and_publish_resource(
        profile: Profile, did: str, options: dict
    ) -> dict:
        """Create, Sign and Publish a Resource."""
        cheqd_manager = DidCheqdManager(profile)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise web.HTTPForbidden(reason="No wallet available")
            try:
                # request create resource operation
                create_request_res = await cheqd_manager.registrar.create_resource(
                    did, options
                )

                job_id: str = create_request_res.get("jobId")
                resource_state = create_request_res.get("resourceState")

                LOGGER.debug("JOBID %s", job_id)
                if resource_state.get("state") == "action":
                    signing_requests: dict = resource_state.get("signingRequest")
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await DidCheqdManager.sign_requests(
                        wallet, signing_requests
                    )

                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.create_resource(
                        did,
                        {
                            "jobId": job_id,
                            "secret": {"signingResponse": signed_responses},
                        },
                    )
                    resource_state = publish_resource_res.get("resourceState")
                    if resource_state.get("state") != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.get("reason")}"
                        )
                    return resource_state
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.get("reason")}"
                    )
            except Exception as err:
                raise AnonCredsRegistrationError(f"{err}")
