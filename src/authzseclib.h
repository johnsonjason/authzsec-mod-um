#pragma once
#ifndef AUTHZ_SECLIB
#define AUTHZ_SECLIB
#include <AclAPI.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "sqlite3.h"
#pragma comment(lib, "sqlite3.lib")

typedef enum _security_policy
{
	restricted = 1,
	read_only,
	read_write,
	execute,
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

	auth_zone(const std::wstring& security_zone, security_policy zone_rules);
	void add_location(const std::wstring& location, bool accessibility);
	void free_location(const std::wstring& location);

private:
	std::vector<std::wstring> zone_locations;
	std::vector<std::wstring> exception_directories;
	security_policy zone_accessibility;
	trustee_member member;

	void set_control_attribute(const std::wstring& location, PACL access_control_list, PACL access_control_list_old, bool accessibility);
	inline std::vector<std::pair<std::wstring, DWORD>> enumerate_explicit_controls(EXPLICIT_ACCESSW* entries, ULONG entry_count);
	void database_store_permission_set(const std::vector<std::pair<std::wstring, DWORD>>& explicit_table);
	void save_permissions(const std::wstring& location, PACL access_control_list);
};

#endif
