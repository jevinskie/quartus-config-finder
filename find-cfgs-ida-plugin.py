#!/usr/bin/env python3

from typing import Optional

import ida_funcs
import idautils
from attrs import define
from cxxfilt import demangle
from rich import print


@define
class CfgFunc:
    name: str
    mangled_name: str
    opt_name_arg_num: Optional[int]
    opt_set_arg_num = Optional[int]


def get_funcs():
    return {
        ida_funcs.get_func_name(func_ea): func_ea for func_ea in idautils.Functions()
    }


func_eas = get_funcs()

mangled_cfg_def_enum_names = [
    "_Z10cfg_set_on16CFG_INI_VAR_ENUM",
    "_Z11cfg_set_off16CFG_INI_VAR_ENUM",
    "_Z13cfg_get_value16CFG_INI_VAR_ENUM",
    "_Z13cfg_set_value16CFG_INI_VAR_ENUMPKc",
    "_Z17cfg_get_int_value16CFG_INI_VAR_ENUM",
    "_Z17cfg_set_int_value16CFG_INI_VAR_ENUMi",
    "_Z9cfg_is_on16CFG_INI_VAR_ENUM",
]

mangled_cfg_names = [
    "_Z10cfg_set_onRKSs",
    "_Z11cfg_set_offRKSs",
    "_Z13cfg_get_valuePKc",
    "_Z13cfg_set_valueRKSsS0_",
    "_Z16cfg_is_qexe_modev",
    "_Z17cfg_get_int_valuePKci",
    "_Z17cfg_get_int_valueRKSsi",
    "_Z17cfg_read_ini_fileRKSs",
    "_Z17cfg_read_ini_filev",
    "_Z17cfg_set_int_valuePKci",
    "_Z17cfg_set_int_valueRKSsi",
    "_Z18cfg_close_ini_filev",
    "_Z18cfg_user_ini_is_on18CFG_USER_INI_ENUMSb",
    "_Z19cfg_set_user_ini_on18CFG_USER_INI_ENUMS",
    "_Z20cfg_get_double_valueRKSsd",
    "_Z20cfg_is_qexe_cmd_modev",
    "_Z20cfg_is_qexe_rpt_modev",
    "_Z20cfg_jtag_auto_configv",
    "_Z20cfg_qexe_ini_appliedv",
    "_Z20cfg_set_user_ini_off18CFG_USER_INI_ENUMS",
    "_Z21cfg_get_most_accessedPSt6vectorISt4pairISsSsESaIS1_EE",
    "_Z22cfg_get_user_ini_value18CFG_USER_INI_ENUMS",
    "_Z22cfg_get_user_ini_valuePKc",
    "_Z22cfg_process_ini_stringRKSs",
    "_Z22cfg_set_user_ini_value18CFG_USER_INI_ENUMSPKc",
    "_Z22cfg_set_user_ini_valuePKcS0_",
    "_Z23cfg_force_qexe_mode_offv",
    "_Z23cfg_is_jtag_server_modev",
    "_Z23cfg_is_qexe_ini_appliedv",
    "_Z23cfg_write_user_ini_filev",
    "_Z24cfg_is_benchmarking_modev",
    "_Z25cfg_get_user_ini_ini_desc18CFG_USER_INI_ENUMS",
    "_Z25cfg_read_default_ini_filev",
    "_Z25cfg_read_project_ini_filePKcb",
    "_Z26cfg_check_debug_ini_valuesPbS_Pi",
    "_Z26cfg_get_ini_file_path_namev",
    "_Z26cfg_get_user_ini_int_value18CFG_USER_INI_ENUMS",
    "_Z26cfg_set_user_ini_int_value18CFG_USER_INI_ENUMSi",
    "_Z27cfg_get_user_ini_ini_string18CFG_USER_INI_ENUMS",
    "_Z31cfg_get_used_variable_value_mapPSt3mapISsSsSt4lessISsESaISt4pairIKSsSsEEE",
    "_Z32cfg_does_ini_variable_have_value18CFG_USER_INI_ENUMSb",
    "_Z32cfg_get_single_most_accessed_iniRSsS_",
    "_Z32cfg_get_user_ini_registry_string18CFG_USER_INI_ENUMS",
    "_Z33cfg_write_and_close_user_ini_filev",
    "_Z34cfg_get_regtest_ini_file_path_namev",
    "_Z39cfg_get_user_ini_registry_branch_string18CFG_USER_INI_ENUMS",
    "_Z43cfg_get_user_ini_registry_sub_branch_string18CFG_USER_INI_ENUMS",
    "_Z47cfg_get_appended_envrionment_ini_file_path_namev",
    "_Z9cfg_is_onPKcb",
    "cfg_dyn_get_int_value",
    "cfg_dyn_get_value",
    "cfg_dyn_is_on",
    "cfg_ini_get_value_for_mega",
]

for mangled in mangled_cfg_names:
    print(demangle(mangled))

# cfg_funcs = {
#     CfgFunc(k, )
# }
# cfg_is_on_ea = func_eas["_Z9cfg_is_onPKcb"]

# print(cfg_is_on_ea)

print()
