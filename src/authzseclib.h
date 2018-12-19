#ifndef AUTHZ_SECLIB
#define AUTHZ_SECLIB
#include <AclAPI.h>
#include <lmcons.h>
#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <algorithm>
#include "sqlite3.h"
#pragma comment(lib, "sqlite3.lib")

typedef struct _GENERIC_ACE {
	ACE_HEADER Header;
	ACCESS_MASK Mask;
	DWORD SidStart;
} ACCESS_GENERIC_ACE;

typedef enum _security_policy
{
	restricted = NULL,
	full_control = GENERIC_ALL,
	read_only = GENERIC_READ,
	read_write = GENERIC_READ | GENERIC_WRITE,
	write = GENERIC_WRITE,
	execute = GENERIC_EXECUTE,
	standard,
	administrator,
} security_policy;

typedef struct _trustee_member
{
	std::wstring name;
	bool group;
} trustee_member;

typedef enum _authzsec_exception
{
	zone_not_found
} authzsec_exception;

class auth_zone
{
public:
	std::wstring name;
	std::vector<std::wstring> standard_sids;

	auth_zone(const std::wstring& trustee_name, const std::wstring& security_zone, security_policy zone_rules);
	void add_location(const std::wstring& location);
	void free_location(const std::wstring& location);

private:
	std::vector<std::wstring> zone_locations;
	std::vector<std::wstring> exception_directories;
	security_policy zone_accessibility;
	trustee_member member;

	void set_control_attribute(const std::wstring& location, PACL access_control_list_old);
	bool lease_access(const std::wstring& location, PACL acl);
	void database_store_permission_set(const std::vector<std::tuple<char, std::wstring, std::wstring, size_t, DWORD>>& entries);
	bool is_primary_sid(const std::wstring& sid_username);
};

#endif
