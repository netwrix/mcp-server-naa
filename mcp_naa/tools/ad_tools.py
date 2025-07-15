from typing import Optional
from .. import app
from .. import database
from .db_tools import run_query # Reuse the run_query tool for execution and formatting
from ..logging_config import get_logger
import pyodbc

logger = get_logger(__name__)

def _run_predefined_query(query: str, tool_name: str) -> str:
    """Checks connection and executes a query using the run_query tool."""
    if not database.get_connection():
        return "Not connected to a database. Please connect first."
    try:
        logger.debug(f"Executing predefined query for {tool_name}")
        # We call the run_query *tool function* which handles execution,
        # formatting, and error reporting specific to tools.
        return run_query(query)
    except Exception as e:
        # Catch unexpected errors during the call itself
        logger.error(f"Unexpected error in {tool_name} wrapper: {e}", exc_info=True)
        return f"An unexpected error occurred while preparing the query for {tool_name}."


@app.mcp.tool("Get-ADEffectiveMembership")
def get_effective_group_members(
    group_dn_filter: Optional[str] = None,
    group_nt_account_filter: Optional[str] = None,
    member_dn_filter: Optional[str] = None,
    member_nt_account_filter: Optional[str] = None,
    member_object_class_filter: Optional[str] = None,
    group_sid_filter: Optional[str] = None,
    member_sid_filter: Optional[str] = None
) -> str:
    """
    Discovers the effective membership of groups in Active Directory, with optional filters.
    Returns a list of groups, members, and their nesting levels matching the criteria.
    Filters use SQL LIKE logic; include wildcards (%) where needed (e.g., '%Admin%', 'Domain\\User%').

    Args:
        group_dn_filter: Optional filter (LIKE) for GroupDistinguishedName.
        group_nt_account_filter: Optional filter (LIKE) for GroupNTAccount (e.g., 'DOMAIN\\GroupName%').
        member_dn_filter: Optional filter (LIKE) for MemberDistinguishedName.
        member_nt_account_filter: Optional filter (LIKE) for MemberNTAccount.
        member_object_class_filter: Optional filter (LIKE) for MemberObjectClassName (e.g., 'user', 'group').
        group_sid_filter: Optional filter (LIKE) for GroupObjectSid (e.g., 'S-1-5-%').
        member_sid_filter: Optional filter (LIKE) for MemberObjectSid.
    """
    tool_name = "Get-ADEffectiveMembership"
    logger.info(f"Tool '{tool_name}' called with filters: "
                f"GroupDN='{group_dn_filter}', GroupNT='{group_nt_account_filter}', "
                f"MemberDN='{member_dn_filter}', MemberNT='{member_nt_account_filter}', "
                f"MemberClass='{member_object_class_filter}', GroupSID='{group_sid_filter}', "
                f"MemberSID='{member_sid_filter}'")

    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Base query structure
    base_query = """
    SELECT
        GroupDistinguishedName,
        GroupDomainCanonicalName,
        GroupNTAccount,
        GroupObjectSid,
        MemberDistinguishedName,
        MemberDomainCanonicalName,
        MemberNTAccount,
        MemberObjectSid,
        MemberObjectClassName,
        MinNestingLevel AS NestingLevel
    FROM
        SA_ADInventory_EffectiveGroupMembersView with (nolock)
    """

    conditions = []
    params = []

    # Dynamically add WHERE clauses and parameters based on provided filters
    if group_dn_filter:
        conditions.append("GroupDistinguishedName LIKE ?")
        params.append(group_dn_filter)
    if group_nt_account_filter:
        conditions.append("GroupNTAccount LIKE ?")
        params.append(group_nt_account_filter)
    if group_sid_filter:
        conditions.append("GroupObjectSid LIKE ?")
        params.append(group_sid_filter)
    if member_dn_filter:
        conditions.append("MemberDistinguishedName LIKE ?")
        params.append(member_dn_filter)
    if member_nt_account_filter:
        conditions.append("MemberNTAccount LIKE ?")
        params.append(member_nt_account_filter)
    if member_sid_filter:
        conditions.append("MemberObjectSid LIKE ?")
        params.append(member_sid_filter)
    if member_object_class_filter:
        conditions.append("MemberObjectClassName LIKE ?")
        params.append(member_object_class_filter)

    final_query = base_query
    if conditions:
        final_query += " WHERE " + " AND ".join(conditions)

    # Add ordering for consistent results
    final_query += " ORDER BY GroupNTAccount, MemberNTAccount;"

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        # Execute the potentially parameterized query directly using the database module
        rows, columns, _ = database.execute_query(final_query, tuple(params))
        if not rows and conditions:
             return f"No effective group memberships found matching the specified filters."
        elif not rows:
             return f"No effective group memberships found in the view." # Should be unlikely unless table is empty

        # Format results using the helper from the database module
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting effective memberships (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting effective memberships: {e}"

@app.mcp.tool("Get-ADExceptions")
def get_ad_exceptions(
    name_filter: Optional[str] = None,
    description_filter: Optional[str] = None,
    principal_nt_account_filter: Optional[str] = None,
    object_class_filter: Optional[str] = None
) -> str:
    """
    Retrieves a list of exceptions defined in the AD inventory, with optional filters.
    Shows exception name, description, associated principal (NT Account), and object class.
    Filters use SQL LIKE logic; include wildcards (%) where needed (e.g., '%Admin%', 'user%').
    Data is sourced from the SA_ADInventory_ExceptionsView.

    Args:
        name_filter: Optional filter (LIKE) for the exception's 'Name'.
        description_filter: Optional filter (LIKE) for the 'Description'.
        principal_nt_account_filter: Optional filter (LIKE) for 'PrincipalNTAccount'.
        object_class_filter: Optional filter (LIKE) for 'PrincipalObjectClassName' (e.g., 'user', 'group').
    """
    tool_name = "Get-ADExceptions"
    logger.info(f"Tool '{tool_name}' called with filters: "
                f"Name='{name_filter}', Description='{description_filter}', "
                f"Principal='{principal_nt_account_filter}', Class='{object_class_filter}'")

    # Check for database connection
    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Define the base SQL query
    base_query = """
    SELECT
        Name                     AS ExceptionName,
        Description,
        PrincipalNTAccount,
        PrincipalObjectClassName AS ObjectClass
    FROM
        SA_ADInventory_ExceptionsView  with (nolock)
    """

    # --- Dynamic Query Building ---
    conditions = []
    params = []

    if name_filter:
        conditions.append("Name LIKE ?")
        params.append(name_filter)
    if description_filter:
        # Be cautious with filtering large text fields like Description - might be slow
        conditions.append("Description LIKE ?")
        params.append(description_filter)
    if principal_nt_account_filter:
        conditions.append("PrincipalNTAccount LIKE ?")
        params.append(principal_nt_account_filter)
    if object_class_filter:
        conditions.append("PrincipalObjectClassName LIKE ?")
        params.append(object_class_filter)

    final_query = base_query
    if conditions:
        final_query += " WHERE " + " AND ".join(conditions)

    # Add ordering for consistent results
    final_query += " ORDER BY ExceptionName;"
    # --- End Dynamic Query Building ---

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        # Execute the potentially parameterized query
        rows, columns, _ = database.execute_query(final_query, tuple(params))

        # Provide more specific feedback if filters were used
        if not rows:
            if conditions:
                return f"No AD exceptions found matching the specified filters."
            else:
                return "No AD exceptions found in SA_ADInventory_ExceptionsView."

        # Format the results into a string table
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting AD exceptions (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting AD exceptions: {e}"

@app.mcp.tool("Get-ADPermissions")
def get_ad_permissions(
    # Filters for Access Entry details
    access_entry_type_filter: Optional[str] = None,
    access_entry_sid_filter: Optional[str] = None,
    principal_name_filter: Optional[str] = None,
    principal_domain_filter: Optional[str] = None,
    permission_filter: Optional[str] = None,
    apply_to_filter: Optional[str] = None,
    property_name_filter: Optional[str] = None,
    is_inherited_filter: Optional[str] = None, # Use '0' for False, '1' for True

    # Filters for the Object the permission applies TO
    dn_filter: Optional[str] = None,
    object_sid_filter: Optional[str] = None,
    object_class_filter: Optional[str] = None,
    object_domain_filter: Optional[str] = None, # Domain column

    # Filters for the Object Owner
    owner_sid_filter: Optional[str] = None,
    owner_domain_filter: Optional[str] = None

) -> str:
    """
    Retrieves Active Directory permissions from SA_ADPerms_PermissionsView, excluding deleted entries.
    Allows optional filtering on various permission attributes.

    Filters use SQL LIKE logic (include wildcards '%') EXCEPT for 'is_inherited_filter'.
    For 'is_inherited_filter', provide '0' (for False/Not Inherited) or '1' (for True/Inherited).

    Args:
        access_entry_type_filter: Optional filter (LIKE) for AccessEntryType (e.g., 'ALLOW', 'DENY').
        access_entry_sid_filter: Optional filter (LIKE) for AccessEntryObjectSID.
        principal_name_filter: Optional filter (LIKE) for AccessEntryPrincipalName.
        principal_domain_filter: Optional filter (LIKE) for AccessEntryDomain.
        permission_filter: Optional filter (LIKE) for AccessEntryPermission (e.g., 'GenericRead', '%Write%').
        apply_to_filter: Optional filter (LIKE) for AccessEntryApplyTo.
        property_name_filter: Optional filter (LIKE) for AccessEntryPropertyName.
        is_inherited_filter: Optional exact filter for IsInherited ('0' or '1').
        dn_filter: Optional filter (LIKE) for the object's DistinguishedName.
        object_sid_filter: Optional filter (LIKE) for the object's ObjectSid.
        object_class_filter: Optional filter (LIKE) for the object's ObjectClass.
        object_domain_filter: Optional filter (LIKE) for the object's Domain.
        owner_sid_filter: Optional filter (LIKE) for OwnerSid.
        owner_domain_filter: Optional filter (LIKE) for OwnerDomain.
    """
    tool_name = "Get-ADPermissions"
    logger.info(f"Tool '{tool_name}' called with filters.") # Keep log concise

    # Input validation for is_inherited_filter
    validated_is_inherited = None
    if is_inherited_filter is not None:
        if is_inherited_filter == '0':
            validated_is_inherited = 0
        elif is_inherited_filter == '1':
            validated_is_inherited = 1
        else:
            return "Invalid value for is_inherited_filter. Please use '0' or '1'."

    # Check for database connection
    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Define the base SQL query including the mandatory filter
    base_query = """
    SELECT
        AccessEntryType,
        AccessEntryObjectSID,
        AccessEntryPrincipalName,
        AccessEntryDomain,
        AccessEntryPermission,
        AccessEntryApplyTo,
        AccessEntryPropertyName,
        IsInherited,
        DistinguishedName,
        ObjectSid,
        ObjectClass,
        OwnerSid,
        Domain,
        OwnerDomain
    FROM
        SA_ADPerms_PermissionsView  with (nolock)
    WHERE
        isdeleted = 0
    """

    # --- Dynamic Query Building for Optional Filters ---
    conditions = []
    params = []

    # Add LIKE filters
    filter_map_like = {
        "AccessEntryType": access_entry_type_filter,
        "AccessEntryObjectSID": access_entry_sid_filter,
        "AccessEntryPrincipalName": principal_name_filter,
        "AccessEntryDomain": principal_domain_filter,
        "AccessEntryPermission": permission_filter,
        "AccessEntryApplyTo": apply_to_filter,
        "AccessEntryPropertyName": property_name_filter,
        "DistinguishedName": dn_filter,
        "ObjectSid": object_sid_filter,
        "ObjectClass": object_class_filter,
        "OwnerSid": owner_sid_filter,
        "Domain": object_domain_filter, # Object's Domain
        "OwnerDomain": owner_domain_filter
    }

    for column, filter_value in filter_map_like.items():
        if filter_value is not None:
            conditions.append(f"{column} LIKE ?")
            params.append(filter_value)

    # Add exact match filter for IsInherited (if validated)
    if validated_is_inherited is not None:
        conditions.append("IsInherited = ?")
        params.append(validated_is_inherited) # Pass the integer 0 or 1

    # Construct the final query
    final_query = base_query
    if conditions:
        # Append the optional filters using AND
        final_query += " AND " + " AND ".join(conditions)

    # Add ordering
    final_query += " ORDER BY DistinguishedName, AccessEntryPrincipalName;"
    # --- End Dynamic Query Building ---

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        # Execute the potentially parameterized query
        rows, columns, _ = database.execute_query(final_query, tuple(params))

        if not rows:
            if conditions: # Check if optional filters were actually added
                return f"No AD permissions found matching the specified filters (and isdeleted = 0)."
            else:
                return "No non-deleted AD permissions found in SA_ADPerms_PermissionsView."

        # Format the results
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting AD permissions (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting AD permissions: {e}"


@app.mcp.tool("Get-DomainControllers")
def get_domain_controllers() -> str:
    """
    Retrieves a list of domain controllers from the SA_AD_DCSummary_List view.
    """
    tool_name = "Get-DomainControllers"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    select * from SA_AD_DCSummary_List
    """
    return _run_predefined_query(query, tool_name)

@app.mcp.tool("Get-CertificateVulnerabilities")
def get_certificate_vulnerabilities() -> str:
    """
    Retrieves a list of domain controllers from the SA_AD_DCSummary_List view.
    """
    tool_name = "Get-CertificateVulnerabilities"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    select [Certificate Authority], [Name], [Published], [Template Vulnerabilities], [Authority Vulnerabilities]
    from SA_AD_CertificateAudit_Vulnerabilities
    """
    return _run_predefined_query(query, tool_name)

@app.mcp.tool("Get-ADCARights")
def get_adca_rights() -> str:
    """
    Retrieves a list of domain controllers from the SA_AD_DCSummary_List view.
    """
    tool_name = "Get-ADCARights"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    SELECT [Certificate Authority]
    , [CA String]
    , [Domain]
    , [NTAccount]
    , [SID]
    , [Access]
    , [Ace Type]
    , [Direct]
    FROM [SA_AD_CertificateAudit_CARights]
    """
    return _run_predefined_query(query, tool_name)

@app.mcp.tool("Get-ADSecurityAssessment")
def get_ad_security_assessment() -> str:
    """
    Retrieves results from the Access Analyzer AD Security Assessment
    """
    tool_name = "Get-ADSecurityAssessment"
    logger.info(f"Tool '{tool_name}' called.")
    query = """
    select Category, [Check], Finding, Risk from SA_AD_SecurityAssessment_Results
    """
    return _run_predefined_query(query, tool_name)


@app.mcp.tool("Get-ADUsers")
def get_ad_users(
    # --- Identification Filters ---
    domain_id_filter: Optional[str] = None,           # Exact Match (usually numeric)
    domain_name_filter: Optional[str] = None,         # LIKE
    domain_canonical_filter: Optional[str] = None,   # LIKE
    principal_id_filter: Optional[str] = None,       # Exact Match (usually numeric)
    sam_account_name_filter: Optional[str] = None,   # LIKE
    nt_account_filter: Optional[str] = None,         # LIKE
    display_name_filter: Optional[str] = None,       # LIKE
    description_filter: Optional[str] = None,        # LIKE
    usn_filter: Optional[str] = None,                 # LIKE (can be large number)
    object_sid_filter: Optional[str] = None,         # LIKE
    dn_id_filter: Optional[str] = None,               # Exact Match (usually numeric)
    distinguished_name_filter: Optional[str] = None, # LIKE
    cn_filter: Optional[str] = None,                 # LIKE
    employee_id_filter: Optional[str] = None,        # LIKE

    # --- Date/Time Filters ---
    when_created_filter: Optional[str] = None,       # LIKE (e.g., '2024-04%')
    when_changed_filter: Optional[str] = None,       # LIKE
    last_logon_filter: Optional[str] = None,         # LIKE (for LastLogonTimestamp)
    account_expires_filter: Optional[str] = None,    # LIKE (or '0' for never)
    pwd_last_set_filter: Optional[str] = None,       # LIKE (for PwdLastSetDate)

    # --- Contact/Org Filters ---
    mail_filter: Optional[str] = None,               # LIKE
    title_filter: Optional[str] = None,              # LIKE
    company_filter: Optional[str] = None,            # LIKE
    department_filter: Optional[str] = None,         # LIKE
    manager_principal_id_filter: Optional[str] = None, # Exact Match (usually numeric)
    telephone_filter: Optional[str] = None,          # LIKE

    # --- Exchange Filters ---
    legacy_exchange_dn_filter: Optional[str] = None, # LIKE
    home_mdb_filter: Optional[str] = None,           # LIKE
    mailbox_store_filter: Optional[str] = None,      # LIKE
    storage_group_filter: Optional[str] = None,      # LIKE
    exchange_server_filter: Optional[str] = None,    # LIKE

    # --- Account Control Flag Filters (Use '0' or '1') ---
    account_disabled_filter: Optional[str] = None,  # = (ACCOUNTDISABLE)
    homedir_required_filter: Optional[str] = None,  # = (HOMEDIR_REQUIRED)
    lockout_filter: Optional[str] = None,           # = (LOCKOUT)
    passwd_notreqd_filter: Optional[str] = None,    # = (PASSWD_NOTREQD)
    passwd_cant_change_filter: Optional[str] = None,# = (PASSWD_CANT_CHANGE)
    encrypted_pwd_allowed_filter: Optional[str] = None, # = (ENCRYPTED_TEXT_PWD_ALLOWED)
    temp_duplicate_filter: Optional[str] = None,    # = (TEMP_DUPLICATE_ACCOUNT)
    normal_account_filter: Optional[str] = None,    # = (NORMAL_ACCOUNT)
    interdomain_trust_filter: Optional[str] = None, # = (INTERDOMAIN_TRUST_ACCOUNT)
    workstation_trust_filter: Optional[str] = None, # = (WORKSTATION_TRUST_ACCOUNT)
    server_trust_filter: Optional[str] = None,      # = (SERVER_TRUST_ACCOUNT)
    dont_expire_pwd_filter: Optional[str] = None,   # = (DONT_EXPIRE_PASSWORD)
    mns_logon_filter: Optional[str] = None,         # = (MNS_LOGON_ACCOUNT)
    smartcard_required_filter: Optional[str] = None,# = (SMARTCARD_REQUIRED)
    trusted_for_delegation_filter: Optional[str] = None, # = (TRUSTED_FOR_DELEGATION)
    not_delegated_filter: Optional[str] = None,     # = (NOT_DELEGATED)
    use_des_key_filter: Optional[str] = None,       # = (USE_DES_KEY_ONLY)
    dont_req_preauth_filter: Optional[str] = None,  # = (DONT_REQ_PREAUTH)
    password_expired_filter: Optional[str] = None,  # = (PASSWORD_EXPIRED)
    auth_for_delegation_filter: Optional[str] = None # = (TRUSTED_TO_AUTH_FOR_DELEGATION)

) -> str:
    """
    Retrieves Active Directory user details from SA_ADInventory_UsersView, excluding deleted users.
    Allows extensive optional filtering on user attributes.

    Most filters use SQL LIKE logic (include wildcards '%').
    ID filters (DomainId, PrincipalId, DnId, ManagerPrincipalId) use exact match.
    Account Control Flag filters (e.g., account_disabled_filter) require '0' or '1' for exact match.

    Args:
        (Numerous filter arguments - see parameter list above)
    """
    tool_name = "Get-ADUsers"
    logger.info(f"Tool '{tool_name}' called with filters.") # Keep log concise

    # --- Input Validation for Boolean-like Flags ---
    bool_filters = {
        "ACCOUNTDISABLE": account_disabled_filter,
        "HOMEDIR_REQUIRED": homedir_required_filter,
        "LOCKOUT": lockout_filter,
        "PASSWD_NOTREQD": passwd_notreqd_filter,
        "PASSWD_CANT_CHANGE": passwd_cant_change_filter,
        "ENCRYPTED_TEXT_PWD_ALLOWED": encrypted_pwd_allowed_filter,
        "TEMP_DUPLICATE_ACCOUNT": temp_duplicate_filter,
        "NORMAL_ACCOUNT": normal_account_filter,
        "INTERDOMAIN_TRUST_ACCOUNT": interdomain_trust_filter,
        "WORKSTATION_TRUST_ACCOUNT": workstation_trust_filter,
        "SERVER_TRUST_ACCOUNT": server_trust_filter,
        "DONT_EXPIRE_PASSWORD": dont_expire_pwd_filter,
        "MNS_LOGON_ACCOUNT": mns_logon_filter,
        "SMARTCARD_REQUIRED": smartcard_required_filter,
        "TRUSTED_FOR_DELEGATION": trusted_for_delegation_filter,
        "NOT_DELEGATED": not_delegated_filter,
        "USE_DES_KEY_ONLY": use_des_key_filter,
        "DONT_REQ_PREAUTH": dont_req_preauth_filter,
        "PASSWORD_EXPIRED": password_expired_filter,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": auth_for_delegation_filter
    }
    validated_bool_params = {}
    for column, value in bool_filters.items():
        if value is not None:
            if value == '0':
                validated_bool_params[column] = 0
            elif value == '1':
                validated_bool_params[column] = 1
            else:
                return f"Invalid value '{value}' for {column}_filter. Please use '0' or '1'."
    # --- End Validation ---

    # Check for database connection
    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Define the base SQL query including the mandatory filter
    base_query = """
    SELECT
        DomainId, DomainName, DomainCanonicalName, PrincipalId, SamAccountName,
        NTAccount, DisplayName, Description, USN, IsDeleted, ObjectSid, DnId,
        DistinguishedName, Cn, EmployeeId, WhenCreated, WhenChanged, Mail,
        LastLogonTimestamp, AccountExpires, Title, Company, Department,
        ManagerPrincipalId, UserAccountControl, msDSUserAccountControlComputed,
        TelephoneNumber, PwdLastSetDate, LegacyExchangeDN, HomeMDB, MailboxStore,
        StorageGroup, ExchangeServer, ACCOUNTDISABLE, HOMEDIR_REQUIRED, LOCKOUT,
        PASSWD_NOTREQD, PASSWD_CANT_CHANGE, ENCRYPTED_TEXT_PWD_ALLOWED,
        TEMP_DUPLICATE_ACCOUNT, NORMAL_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT,
        WORKSTATION_TRUST_ACCOUNT, SERVER_TRUST_ACCOUNT, DONT_EXPIRE_PASSWORD,
        MNS_LOGON_ACCOUNT, SMARTCARD_REQUIRED, TRUSTED_FOR_DELEGATION,
        NOT_DELEGATED, USE_DES_KEY_ONLY, DONT_REQ_PREAUTH, PASSWORD_EXPIRED,
        TRUSTED_TO_AUTH_FOR_DELEGATION
    FROM
        SA_ADInventory_UsersView  with (nolock)
    WHERE
        IsDeleted = 0
    """

    # --- Dynamic Query Building for Optional Filters ---
    conditions = []
    params = []

    # Map filters requiring LIKE
    like_filter_map = {
        "DomainName": domain_name_filter,
        "DomainCanonicalName": domain_canonical_filter,
        "SamAccountName": sam_account_name_filter,
        "NTAccount": nt_account_filter,
        "DisplayName": display_name_filter,
        "Description": description_filter,
        "USN": usn_filter, # Treat USN as string for LIKE
        "ObjectSid": object_sid_filter,
        "DistinguishedName": distinguished_name_filter,
        "Cn": cn_filter,
        "EmployeeId": employee_id_filter,
        "WhenCreated": when_created_filter,
        "WhenChanged": when_changed_filter,
        "LastLogonTimestamp": last_logon_filter,
        "AccountExpires": account_expires_filter,
        "PwdLastSetDate": pwd_last_set_filter,
        "Mail": mail_filter,
        "Title": title_filter,
        "Company": company_filter,
        "Department": department_filter,
        "TelephoneNumber": telephone_filter,
        "LegacyExchangeDN": legacy_exchange_dn_filter,
        "HomeMDB": home_mdb_filter,
        "MailboxStore": mailbox_store_filter,
        "StorageGroup": storage_group_filter,
        "ExchangeServer": exchange_server_filter,
        # Note: UserAccountControl & msDSUserAccountControlComputed are numeric,
        # but LIKE might be useful if user provides partial bitmask value?
        # If exact numeric match is needed, move to equals_filter_map.
        "UserAccountControl": None, # Example: Not adding filters for these complex fields by default
        "msDSUserAccountControlComputed": None
    }

    for column, filter_value in like_filter_map.items():
        if filter_value is not None:
            conditions.append(f"{column} LIKE ?")
            params.append(filter_value)

    # Map filters requiring =
    equals_filter_map = {
        "DomainId": domain_id_filter,
        "PrincipalId": principal_id_filter,
        "DnId": dn_id_filter,
        "ManagerPrincipalId": manager_principal_id_filter
    }

    for column, filter_value in equals_filter_map.items():
         if filter_value is not None:
            # Could add validation here to ensure value is numeric if needed
            conditions.append(f"{column} = ?")
            params.append(filter_value)

    # Add validated boolean filters
    for column, value in validated_bool_params.items():
         conditions.append(f"{column} = ?")
         params.append(value)


    # Construct the final query
    final_query = base_query
    if conditions:
        # Append the optional filters using AND
        final_query += " AND " + " AND ".join(conditions)

    # Add ordering
    final_query += " ORDER BY NTAccount;"
    # --- End Dynamic Query Building ---

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        rows, columns, _ = database.execute_query(final_query, tuple(params))

        if not rows:
            if conditions: # Check if optional filters were actually added
                return f"No AD users found matching the specified filters (and IsDeleted = 0)."
            else:
                return "No non-deleted AD users found in SA_ADInventory_UsersView."

        # Format the results
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting AD users (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting AD users: {e}"

# Ensure the rest of the file remains valid

@app.mcp.tool("Get-ADGroups")
def get_ad_groups(
    # --- Identification Filters ---
    domain_id_filter: Optional[str] = None,           # Exact Match (usually numeric)
    domain_name_filter: Optional[str] = None,         # LIKE
    domain_canonical_filter: Optional[str] = None,   # LIKE
    principal_id_filter: Optional[str] = None,       # Exact Match (usually numeric)
    sam_account_name_filter: Optional[str] = None,   # LIKE
    nt_account_filter: Optional[str] = None,         # LIKE
    display_name_filter: Optional[str] = None,       # LIKE
    description_filter: Optional[str] = None,        # LIKE
    usn_filter: Optional[str] = None,                 # LIKE (can be large number)
    is_deleted_filter: Optional[str] = None,         # Exact Match ('0' or '1')
    object_sid_filter: Optional[str] = None,         # LIKE
    dn_id_filter: Optional[str] = None,               # Exact Match (usually numeric)
    distinguished_name_filter: Optional[str] = None, # LIKE
    cn_filter: Optional[str] = None,                 # LIKE

    # --- Date Filters ---
    when_created_filter: Optional[str] = None,       # LIKE (e.g., '2024-04%')
    when_changed_filter: Optional[str] = None,       # LIKE

    # --- Group Specific Filters ---
    group_type_filter: Optional[str] = None,         # LIKE (e.g., 'Security', 'Distribution') or numeric value
    group_scope_filter: Optional[str] = None,        # LIKE (e.g., 'Global', 'DomainLocal', 'Universal') or numeric value
    # GroupTarget might be less common to filter on directly? Use LIKE for flexibility
    group_target_filter: Optional[str] = None,       # LIKE

    # --- Other Attributes ---
    mail_filter: Optional[str] = None,               # LIKE
    managed_by_principal_id_filter: Optional[str] = None, # Exact Match (usually numeric)
    # DirectMemberCount filtering might require comparison operators (> < =) rather than LIKE
    # For simplicity with current structure, using LIKE (treat as string) or exact match (=)
    direct_member_count_filter: Optional[str] = None, # = (exact count) or LIKE (less common)

) -> str:
    """
    Retrieves Active Directory group details from SA_ADInventory_GroupsView.
    Allows optional filtering on various group attributes. Includes deleted groups by default.

    Most filters use SQL LIKE logic (include wildcards '%').
    ID filters (DomainId, PrincipalId, DnId, ManagedByPrincipalId) use exact match.
    'is_deleted_filter' requires '0' or '1' for exact match.
    'direct_member_count_filter' uses exact match (=) by default.

    Args:
        (Numerous filter arguments - see parameter list above)
        is_deleted_filter: Optional filter ('0' or '1') to show only non-deleted or only deleted groups.
    """
    tool_name = "Get-ADGroups"
    logger.info(f"Tool '{tool_name}' called with filters.") # Keep log concise

    # --- Input Validation for is_deleted_filter ---
    validated_is_deleted = None
    if is_deleted_filter is not None:
        if is_deleted_filter == '0':
            validated_is_deleted = 0
        elif is_deleted_filter == '1':
            validated_is_deleted = 1
        else:
            return "Invalid value for is_deleted_filter. Please use '0' or '1'."
    # --- End Validation ---

    # Check for database connection
    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Define the base SQL query
    base_query = """
    SELECT
        DomainId, DomainName, DomainCanonicalName, PrincipalId, SamAccountName,
        NTAccount, DisplayName, Description, USN, IsDeleted, ObjectSid, DnId,
        DistinguishedName, Cn, WhenCreated, WhenChanged, GroupType, GroupScope,
        GroupTarget, Mail, ManagedByPrincipalId, DirectMemberCount
    FROM
        SA_ADInventory_GroupsView  with (nolock)
    """

    # --- Dynamic Query Building for Optional Filters ---
    conditions = []
    params = []

    # Map filters requiring LIKE
    like_filter_map = {
        "DomainName": domain_name_filter,
        "DomainCanonicalName": domain_canonical_filter,
        "SamAccountName": sam_account_name_filter,
        "NTAccount": nt_account_filter,
        "DisplayName": display_name_filter,
        "Description": description_filter,
        "USN": usn_filter, # Treat USN as string for LIKE
        "ObjectSid": object_sid_filter,
        "DistinguishedName": distinguished_name_filter,
        "Cn": cn_filter,
        "WhenCreated": when_created_filter,
        "WhenChanged": when_changed_filter,
        "GroupType": group_type_filter,
        "GroupScope": group_scope_filter,
        "GroupTarget": group_target_filter,
        "Mail": mail_filter,
        # "DirectMemberCount": direct_member_count_filter, # Using = below
    }

    for column, filter_value in like_filter_map.items():
        if filter_value is not None:
            conditions.append(f"{column} LIKE ?")
            params.append(filter_value)

    # Map filters requiring =
    equals_filter_map = {
        "DomainId": domain_id_filter,
        "PrincipalId": principal_id_filter,
        "DnId": dn_id_filter,
        "ManagedByPrincipalId": managed_by_principal_id_filter,
        "DirectMemberCount": direct_member_count_filter # Using = for count
    }

    for column, filter_value in equals_filter_map.items():
         if filter_value is not None:
            # Could add validation here to ensure value is numeric if needed
            conditions.append(f"{column} = ?")
            params.append(filter_value)

    # Add validated is_deleted filter (if provided)
    if validated_is_deleted is not None:
         conditions.append(f"IsDeleted = ?")
         params.append(validated_is_deleted)


    # Construct the final query
    final_query = base_query
    if conditions:
        # Append the optional filters using WHERE or AND
        final_query += " WHERE " + " AND ".join(conditions)

    # Add ordering
    final_query += " ORDER BY NTAccount;"
    # --- End Dynamic Query Building ---

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        # Execute the potentially parameterized query
        rows, columns, _ = database.execute_query(final_query, tuple(params))

        if not rows:
            if conditions: # Check if optional filters were actually added
                return f"No AD groups found matching the specified filters."
            else:
                return "No AD groups found in SA_ADInventory_GroupsView."

        # Format the results
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting AD groups (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting AD groups: {e}"

@app.mcp.tool("Get-ADComputers")
def get_ad_computers(
    # --- Identification Filters ---
    domain_id_filter: Optional[str] = None,           # Exact Match (usually numeric)
    domain_name_filter: Optional[str] = None,         # LIKE
    domain_canonical_filter: Optional[str] = None,   # LIKE
    principal_id_filter: Optional[str] = None,       # Exact Match (usually numeric)
    sam_account_name_filter: Optional[str] = None,   # LIKE (Often ends with $)
    nt_account_filter: Optional[str] = None,         # LIKE
    display_name_filter: Optional[str] = None,       # LIKE
    description_filter: Optional[str] = None,        # LIKE
    usn_filter: Optional[str] = None,                 # LIKE (can be large number)
    object_sid_filter: Optional[str] = None,         # LIKE
    distinguished_name_filter: Optional[str] = None, # LIKE
    cn_filter: Optional[str] = None,                 # LIKE

    # --- Date/Time Filters ---
    when_created_filter: Optional[str] = None,       # LIKE (e.g., '2024-04%')
    when_changed_filter: Optional[str] = None,       # LIKE
    last_logon_filter: Optional[str] = None,         # LIKE (for LastLogonTimestamp)
    pwd_last_set_filter: Optional[str] = None,       # LIKE (for PwdLastSetDate)

    # --- Computer Specific Filters ---
    dns_hostname_filter: Optional[str] = None,       # LIKE
    os_filter: Optional[str] = None,                 # LIKE (OperatingSystem)
    os_version_filter: Optional[str] = None,         # LIKE (OperatingSystemVersion)
    os_sp_filter: Optional[str] = None,              # LIKE (OperatingSystemServicePack)
    location_filter: Optional[str] = None,           # LIKE

    # --- Management Filter ---
    managed_by_principal_id_filter: Optional[str] = None, # Exact Match (usually numeric)

    # --- Account Control Flag Filters (Use '0' or '1') ---
    account_disabled_filter: Optional[str] = None,  # = (ACCOUNTDISABLE)
    homedir_required_filter: Optional[str] = None,  # = (HOMEDIR_REQUIRED)
    lockout_filter: Optional[str] = None,           # = (LOCKOUT)
    passwd_notreqd_filter: Optional[str] = None,    # = (PASSWD_NOTREQD)
    passwd_cant_change_filter: Optional[str] = None,# = (PASSWD_CANT_CHANGE)
    encrypted_pwd_allowed_filter: Optional[str] = None, # = (ENCRYPTED_TEXT_PWD_ALLOWED)
    temp_duplicate_filter: Optional[str] = None,    # = (TEMP_DUPLICATE_ACCOUNT)
    normal_account_filter: Optional[str] = None,    # = (NORMAL_ACCOUNT)
    interdomain_trust_filter: Optional[str] = None, # = (INTERDOMAIN_TRUST_ACCOUNT)
    workstation_trust_filter: Optional[str] = None, # = (WORKSTATION_TRUST_ACCOUNT)
    server_trust_filter: Optional[str] = None,      # = (SERVER_TRUST_ACCOUNT)
    dont_expire_pwd_filter: Optional[str] = None,   # = (DONT_EXPIRE_PASSWORD)
    mns_logon_filter: Optional[str] = None,         # = (MNS_LOGON_ACCOUNT)
    smartcard_required_filter: Optional[str] = None,# = (SMARTCARD_REQUIRED)
    trusted_for_delegation_filter: Optional[str] = None, # = (TRUSTED_FOR_DELEGATION)
    not_delegated_filter: Optional[str] = None,     # = (NOT_DELEGATED)
    use_des_key_filter: Optional[str] = None,       # = (USE_DES_KEY_ONLY)
    dont_req_preauth_filter: Optional[str] = None,  # = (DONT_REQ_PREAUTH)
    password_expired_filter: Optional[str] = None,  # = (PASSWORD_EXPIRED)
    auth_for_delegation_filter: Optional[str] = None # = (TRUSTED_TO_AUTH_FOR_DELEGATION)

) -> str:
    """
    Retrieves Active Directory computer details from SA_ADInventory_ComputersView, excluding deleted computers.
    Allows extensive optional filtering on computer attributes.

    Most filters use SQL LIKE logic (include wildcards '%').
    ID filters (DomainId, PrincipalId, ManagedByPrincipalId) use exact match.
    Account Control Flag filters (e.g., account_disabled_filter) require '0' or '1' for exact match.

    Args:
        (Numerous filter arguments - see parameter list above)
    """
    tool_name = "Get-ADComputers"
    logger.info(f"Tool '{tool_name}' called with filters.") # Keep log concise

    # --- Input Validation for Boolean-like Flags ---
    bool_filters = {
        "ACCOUNTDISABLE": account_disabled_filter,
        "HOMEDIR_REQUIRED": homedir_required_filter,
        "LOCKOUT": lockout_filter,
        "PASSWD_NOTREQD": passwd_notreqd_filter,
        "PASSWD_CANT_CHANGE": passwd_cant_change_filter,
        "ENCRYPTED_TEXT_PWD_ALLOWED": encrypted_pwd_allowed_filter,
        "TEMP_DUPLICATE_ACCOUNT": temp_duplicate_filter,
        "NORMAL_ACCOUNT": normal_account_filter,
        "INTERDOMAIN_TRUST_ACCOUNT": interdomain_trust_filter,
        "WORKSTATION_TRUST_ACCOUNT": workstation_trust_filter,
        "SERVER_TRUST_ACCOUNT": server_trust_filter,
        "DONT_EXPIRE_PASSWORD": dont_expire_pwd_filter,
        "MNS_LOGON_ACCOUNT": mns_logon_filter,
        "SMARTCARD_REQUIRED": smartcard_required_filter,
        "TRUSTED_FOR_DELEGATION": trusted_for_delegation_filter,
        "NOT_DELEGATED": not_delegated_filter,
        "USE_DES_KEY_ONLY": use_des_key_filter,
        "DONT_REQ_PREAUTH": dont_req_preauth_filter,
        "PASSWORD_EXPIRED": password_expired_filter,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": auth_for_delegation_filter
    }
    validated_bool_params = {}
    for column, value in bool_filters.items():
        if value is not None:
            if value == '0':
                validated_bool_params[column] = 0
            elif value == '1':
                validated_bool_params[column] = 1
            else:
                return f"Invalid value '{value}' for {column}_filter. Please use '0' or '1'."
    # --- End Validation ---

    # Check for database connection
    if not database.get_connection():
        return "Not connected to a database. Please connect first."

    # Define the base SQL query including the mandatory filter
    base_query = """
    SELECT
        DomainId, DomainName, DomainCanonicalName, PrincipalId, SamAccountName,
        NTAccount, DisplayName, Description, USN, IsDeleted, ObjectSid,
        DistinguishedName, Cn, WhenCreated, WhenChanged, DnsHostName,
        OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack,
        ManagedByPrincipalId, Location, LastLogonTimestamp, PwdLastSetDate,
        UserAccountControl, ACCOUNTDISABLE, HOMEDIR_REQUIRED, LOCKOUT,
        PASSWD_NOTREQD, PASSWD_CANT_CHANGE, ENCRYPTED_TEXT_PWD_ALLOWED,
        TEMP_DUPLICATE_ACCOUNT, NORMAL_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT,
        WORKSTATION_TRUST_ACCOUNT, SERVER_TRUST_ACCOUNT, DONT_EXPIRE_PASSWORD,
        MNS_LOGON_ACCOUNT, SMARTCARD_REQUIRED, TRUSTED_FOR_DELEGATION,
        NOT_DELEGATED, USE_DES_KEY_ONLY, DONT_REQ_PREAUTH, PASSWORD_EXPIRED,
        TRUSTED_TO_AUTH_FOR_DELEGATION
    FROM
        SA_ADInventory_ComputersView with (nolock)
    WHERE
        IsDeleted = 0
    """

    # --- Dynamic Query Building for Optional Filters ---
    conditions = []
    params = []

    # Map filters requiring LIKE
    like_filter_map = {
        "DomainName": domain_name_filter,
        "DomainCanonicalName": domain_canonical_filter,
        "SamAccountName": sam_account_name_filter,
        "NTAccount": nt_account_filter,
        "DisplayName": display_name_filter,
        "Description": description_filter,
        "USN": usn_filter, # Treat USN as string for LIKE
        "ObjectSid": object_sid_filter,
        "DistinguishedName": distinguished_name_filter,
        "Cn": cn_filter,
        "WhenCreated": when_created_filter,
        "WhenChanged": when_changed_filter,
        "LastLogonTimestamp": last_logon_filter,
        "PwdLastSetDate": pwd_last_set_filter,
        "DnsHostName": dns_hostname_filter,
        "OperatingSystem": os_filter,
        "OperatingSystemVersion": os_version_filter,
        "OperatingSystemServicePack": os_sp_filter,
        "Location": location_filter,
        # Note: UserAccountControl is numeric, but LIKE might be useful? See Users tool notes.
        "UserAccountControl": None # Example: Not adding filters for this complex field by default
    }

    for column, filter_value in like_filter_map.items():
        if filter_value is not None:
            conditions.append(f"{column} LIKE ?")
            params.append(filter_value)

    # Map filters requiring =
    equals_filter_map = {
        "DomainId": domain_id_filter,
        "PrincipalId": principal_id_filter,
        "ManagedByPrincipalId": managed_by_principal_id_filter
    }

    for column, filter_value in equals_filter_map.items():
         if filter_value is not None:
            # Could add validation here to ensure value is numeric if needed
            conditions.append(f"{column} = ?")
            params.append(filter_value)

    # Add validated boolean filters
    for column, value in validated_bool_params.items():
         conditions.append(f"{column} = ?")
         params.append(value)


    # Construct the final query
    final_query = base_query
    if conditions:
        # Append the optional filters using AND
        final_query += " AND " + " AND ".join(conditions)

    # Add ordering
    final_query += " ORDER BY NTAccount;"
    # --- End Dynamic Query Building ---

    logger.debug(f"Constructed query for {tool_name}: {final_query}")
    logger.debug(f"Query parameters: {tuple(params)}")

    try:
        # Execute the potentially parameterized query
        rows, columns, _ = database.execute_query(final_query, tuple(params))

        if not rows:
            if conditions: # Check if optional filters were actually added
                return f"No AD computers found matching the specified filters (and IsDeleted = 0)."
            else:
                return "No non-deleted AD computers found in SA_ADInventory_ComputersView."

        # Format the results
        return database.format_results(rows, columns)

    except pyodbc.Error as e:
        logger.error(f"Database error executing {tool_name} query: {e}", exc_info=True)
        sqlstate = e.args[0] if e.args else 'N/A'
        return f"Database error getting AD computers (SQLSTATE: {sqlstate}): {e}"
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name}: {e}", exc_info=True)
        return f"An unexpected error occurred while getting AD computers: {e}"