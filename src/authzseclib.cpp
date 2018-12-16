// authzseclib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "authzseclib.h"

auth_zone::auth_zone(const std::wstring& trustee_name, const std::wstring& security_zone, security_policy zone_rules)
{
	this->name = security_zone;
	this->zone_accessibility = zone_rules;
	this->member.group = false;
	this->member.name = trustee_name;
}


void auth_zone::add_location(const std::wstring& location, bool accessibility)
{
	PACL access_control_list_old = NULL;

	GetNamedSecurityInfoW(location.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
		&access_control_list_old, NULL, NULL);

	if (!access_control_list_old)
	{
		std::cout << "Error getting named security information." << std::endl;
		return;
	}

	switch (this->zone_accessibility)
	{
	case read_only:
	case read_write:
	case execute:
		set_control_attribute(location, access_control_list_old, accessibility);
	case restricted:
		break;
	case standard:
		break;
	case administrator:
		break;
	}

	this->zone_locations.push_back(location);
	save_permissions(location, access_control_list_old);
}

PACL auth_zone::renew_access(const std::wstring& location, PACL acl)
{
	// access=allowed/denied
	// <access:Location:SIDString:ACEIndex:Permission>
	std::vector<std::tuple<char, std::wstring, std::wstring, size_t, DWORD>> entries;

	DWORD user_length = UNLEN;
	DWORD domain_length = DNLEN;

	WCHAR* username = new TCHAR[user_length];
	WCHAR* domain = new TCHAR[domain_length];

	for (size_t acindex = 0; acindex < acl->AceCount; acindex++)
	{
		generic_ace* ace;
		GetAce(acl, acindex, reinterpret_cast<PVOID*>(&ace));
		if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			SID *sid;
			SID_NAME_USE sid_type;
			
			if (LookupAccountSidW(NULL, sid, username, &user_length, domain, &domain_length, &sid_type))
			{
				entries.push_back(std::make_tuple('a', location, std::wstring(username), acindex, ace->Mask));
			}
		}
		else if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
		{
			SID *sid;
			SID_NAME_USE sid_type;
			if (LookupAccountSidW(NULL, sid, username, &user_length, domain, &domain_length, &sid_type))
			{
				entries.push_back(std::make_tuple('d', location, std::wstring(username), acindex, ace->Mask));
			}
		}
	}

	delete[] username;
	delete[] domain;
}

void auth_zone::set_control_attribute(const std::wstring& location, PACL access_control_list_old, bool accessibility)
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
		PACL access_control_list = renew_access(location, access_control_list_old);
		SetNamedSecurityInfoW(const_cast<LPWSTR>(location.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
			access_control_list, NULL);
	}
}


inline std::vector<std::pair<std::wstring, DWORD>> auth_zone::enumerate_explicit_controls(EXPLICIT_ACCESSW* entries, ULONG entry_count)
{
	std::vector<std::pair<std::wstring, DWORD>> ac_pair;
	for (size_t i = 0; i < entry_count; i++)
	{
		ac_pair.push_back({ std::wstring(entries[i].Trustee.ptstrName), entries[i].grfAccessPermissions });
	}
	return ac_pair;
}

static int sqlite_exec_callback(void* reserved, int argc, char** argv, char** az_colname)
{
	for (int i = 0; i < argc; i++)
	{
		std::cout << az_colname << (argv[i] ? argv[i] : "NULL") << '\n';
	}
	return 0;
}


static std::vector<std::string> enumerate_set_controls(sqlite3* database, const std::wstring& object_name, const std::vector<std::pair<std::wstring, DWORD>>& explicit_table)
{
	std::string ascii_objname(object_name.begin(), object_name.end());
	std::vector<std::string> queries;
	for (auto entry : explicit_table)
	{
		queries.push_back("INSERT INTO '" + ascii_objname + "'(trustee, permission) " \
			"VALUES ( '" + std::string(entry.first.begin(), entry.first.end()) + "', " + std::to_string(entry.second) + " );");
	}
	return queries;
}

void auth_zone::database_store_permission_set(const std::wstring& location, const std::vector<std::pair<std::wstring, DWORD>>& explicit_table)
{
	sqlite3* database;
	char* error_msg = NULL;
	int result = 0;

	std::string authzsec_table = "CREATE TABLE IF NOT EXISTS '" + std::string(location.begin(), location.end()) + "'(trustee TEXT, permission INT)";
	
	result = sqlite3_open("authzsec_store.db", &database);
	result = sqlite3_exec(database, authzsec_table.c_str(), sqlite_exec_callback, 0, &error_msg);
	std::vector<std::string> queries = enumerate_set_controls(database, location, explicit_table);

	for (std::string query : queries)
	{
		sqlite3_exec(database, query.c_str(), sqlite_exec_callback, 0, &error_msg);
	}

	result = sqlite3_close(database);
}

void auth_zone::save_permissions(const std::wstring& location, PACL access_control_list)
{
	if (std::find(this->zone_locations.begin(), this->zone_locations.end(), location) == this->zone_locations.end())
	{
		throw authzsec_exception::zone_not_found;
	}

	ULONG entry_count;
	EXPLICIT_ACCESSW* entries;
	std::cout << GetExplicitEntriesFromAclW(access_control_list, &entry_count, &entries) << std::endl;

	if (entries != NULL)
	{
		database_store_permission_set(location, enumerate_explicit_controls(entries, entry_count));
		LocalFree(entries);
	}
}
