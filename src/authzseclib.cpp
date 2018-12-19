#include "stdafx.h"
#include "authzseclib.h"

auth_zone::auth_zone(const std::wstring& trustee_name, const std::wstring& security_zone, security_policy zone_rules)
{
	this->name = security_zone;
	this->zone_accessibility = zone_rules;
	this->member.group = false;
	this->member.name = trustee_name;
}


void auth_zone::add_location(const std::wstring& location)
{
	PACL access_control_list_old = NULL;

	GetNamedSecurityInfoW(location.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
		&access_control_list_old, NULL, NULL);

	if (!access_control_list_old)
	{
		std::cerr << "Error getting named security information.\n";
		return;
	}

	switch (this->zone_accessibility)
	{
	case read_only:
	case read_write:
	case execute:
	case full_control:
		set_control_attribute(location, access_control_list_old);
	case restricted:
		break;
	case standard:
		break;
	case administrator:
		break;
	}

	this->zone_locations.push_back(location);
}

bool auth_zone::is_primary_sid(const std::wstring& sid_username)
{
	for (const std::wstring& sid : this->standard_sids)
	{
		if (sid_username == sid)
		{
			return true;
		}
	}
	return false;
}

static DWORD reverse_permission_mask_deny(security_policy policy)
{
	switch (policy)
	{
	case security_policy::read_only:
		return GENERIC_WRITE | GENERIC_EXECUTE;
	case security_policy::write:
		return GENERIC_READ | GENERIC_EXECUTE;
	case security_policy::execute:
		return GENERIC_WRITE;
	}
	return NULL;
}

bool auth_zone::lease_access(const std::wstring& location, PACL acl)
{
	// access=allowed/denied
	// <access:Location:SIDString:ACEIndex:Permission>
	std::vector<std::tuple<char, std::wstring, std::wstring, size_t, DWORD>> entries;
	DWORD user_length = UNLEN;
	DWORD domain_length = UNLEN;
	WCHAR* username = new TCHAR[user_length];
	WCHAR* domain = new TCHAR[domain_length];

	for (size_t acindex = 0; acindex < acl->AceCount; acindex++)
	{
		/* Redefining the lengths because the lookup routine will modify them */
		user_length = UNLEN;
		domain_length = UNLEN;
		ACCESS_GENERIC_ACE* ace;

		GetAce(acl, acindex, reinterpret_cast<PVOID*>(&ace));
		if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			SID* sid = reinterpret_cast<SID*>(&reinterpret_cast<ACCESS_GENERIC_ACE*>(ace)->SidStart);
			SID_NAME_USE sid_type;
			
			if (LookupAccountSidW(NULL, sid, username, &user_length, domain, &domain_length, &sid_type))
			{
				if (!is_primary_sid(std::wstring(username)))
				{
					entries.push_back(std::make_tuple('a', location, std::wstring(username), acindex, ace->Mask));
					ace->Mask = this->zone_accessibility;
				}
			}
			else
			{
				return false;
			}
		}
		else if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
		{
			SID* sid = reinterpret_cast<SID*>(&reinterpret_cast<ACCESS_GENERIC_ACE*>(ace)->SidStart);
			SID_NAME_USE sid_type;
			if (LookupAccountSidW(NULL, sid, username, &user_length, domain, &domain_length, &sid_type))
			{
				if (!is_primary_sid(std::wstring(username)))
				{
					entries.push_back(std::make_tuple('d', location, std::wstring(username), acindex, ace->Mask));
					ace->Mask = reverse_permission_mask_deny(this->zone_accessibility);
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	delete[] username;
	delete[] domain;
	database_store_permission_set(entries);
	SetNamedSecurityInfoW(const_cast<LPWSTR>(location.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
	return true;
}

void auth_zone::set_control_attribute(const std::wstring& location, PACL access_control_list_old)
{
	switch (this->zone_accessibility)
	{
	case restricted:
		break;
	case standard:
		break;
	case administrator:
		break;
	default:
		lease_access(location, access_control_list_old);
	}
}

static int sqlite_exec_callback(void* reserved, int argc, char** argv, char** az_colname)
{
	for (size_t i = 0; i < argc; i++)
	{
		std::cout << az_colname << (argv[i] ? argv[i] : "NULL") << '\n';
	}
	return 0;
}

static std::string get_mask(DWORD mask)
{
	std::string permission;
	if (FILE_READ_DATA & mask) 
	{
		permission += "READ_";
	}
	if (FILE_WRITE_DATA & mask) 
	{
		permission += "WRITE_";
	}
	if (FILE_EXECUTE & mask) 
	{
		permission += "EXECUTE_";
	}
	return permission;
}


static std::vector<std::string> enumerate_set_controls(const std::string& objname, const std::vector<std::tuple<char, std::wstring, std::wstring, size_t, DWORD>>& entries)
{
	std::vector<std::string> queries;

	for (auto entry : entries)
	{
		std::string location(std::get<1>(entry).begin(), std::get<1>(entry).end());
		std::string sid_string(std::get<2>(entry).begin(), std::get<2>(entry).end());
		std::string permission = get_mask(std::get<4>(entry));

		queries.push_back("INSERT INTO '" + objname +
			"'(Access, Location, SIDString, ACEIndex, Permission) " \
			"VALUES ('" + std::get<0>(entry) + "', '" + location + "', '" + sid_string + "', " + std::to_string(std::get<3>(entry)) + ", '" + permission + "'" + ")");
	}
	return queries;
}

void auth_zone::database_store_permission_set(const std::vector<std::tuple<char, std::wstring, std::wstring, size_t, DWORD>>& entries)
{
	sqlite3* database;
	char* error_msg = NULL;
	int result = 0;

	std::string authzsec_table = "CREATE TABLE IF NOT EXISTS '" + std::string(this->name.begin(), this->name.end()) + "'(Access TEXT, Location TEXT, SIDString TEXT, ACEIndex INT," + 
		"Permission TEXT)";
	
	result = sqlite3_open("authzsec_store.db", &database);
	result = sqlite3_exec(database, authzsec_table.c_str(), sqlite_exec_callback, 0, &error_msg);
	std::vector<std::string> queries = enumerate_set_controls(std::string(this->name.begin(), this->name.end()), entries);

	for (std::string query : queries)
	{
		std::cout << query.c_str() << std::endl;
		sqlite3_exec(database, query.c_str(), sqlite_exec_callback, 0, &error_msg);
	}

	result = sqlite3_close(database);
}
