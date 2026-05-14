void FUN_140016820(longlong *param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined8 *puVar4;
  LPCWSTR ******pppppppWVar5;
  undefined8 *******pppppppuVar6;
  ulonglong uVar7;
  undefined1 auStackY_508 [32];
  HMODULE *local_4c8;
  int local_4c0;
  undefined4 local_4b8 [2];
  LPCWSTR ******local_4b0 [2];
  undefined8 local_4a0;
  ulonglong uStack_498;
  undefined8 *******local_490 [2];
  ulonglong local_480;
  ulonglong local_478;
  undefined8 local_470 [5];
  DWORD local_448;
  wchar_t local_444 [260];
  wchar_t local_23c [266];
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_508;
  local_448 = timeGetTime();
  uVar7 = 0xffffffffffffffff;
  wcsncpy_s(local_444,0x102,L"service::is_command_trusted",0xffffffffffffffff);
  wcscat_s(local_444,0x104,L"()");
  wcsncpy_s(local_23c,0x104,L"service::is_command_trusted",0xffffffffffffffff);
  if (DAT_14007d500 + DAT_14007d504 != 0) {
    local_4c8 = FUN_14000eb20();
    LOCK();
    local_4c0 = 1;
    UNLOCK();
    if (local_4c8 == (HMODULE *)0x0) {
      local_4c8 = FUN_14000eb20();
      LOCK();
      local_4c0 = 2;
      UNLOCK();
    }
    local_4b8[0] = 0x20;
    FUN_1400019c0((longlong)local_4c8,1,local_4b8,&IMAGE_DOS_HEADER_140000000,local_23c,L"-> %s");
    LOCK();
    UNLOCK();
    iVar1 = local_4c0 + -1;
    iVar3 = local_4c0;
    while (-1 < iVar1) {
      local_4c0 = iVar3 + -1;
      FUN_140011e70();
      LOCK();
      UNLOCK();
      iVar1 = iVar3 + -2;
      iVar3 = local_4c0;
    }
    LOCK();
    UNLOCK();
  }
  local_480 = 0;
  local_478 = 7;
  local_490[0] = (undefined8 *******)0x0;
  FUN_140010340((longlong *)local_490,(undefined8 *)L"bdservicehost.",0xe);
  puVar4 = (undefined8 *)(*(code *)PTR__guard_dispatch_icall_14005b538)(param_1);
  do {
    uVar7 = uVar7 + 1;
  } while (*(short *)((longlong)puVar4 + uVar7 * 2) != 0);
  FUN_14000e630(local_490,puVar4,uVar7);
  pppppppuVar6 = local_490;
  if (7 < local_478) {
    pppppppuVar6 = local_490[0];
  }
  local_4b0[0] = (LPCWSTR ******)0x0;
  local_4a0 = 0;
  uStack_498 = 7;
  FUN_140010340((longlong *)local_4b0,pppppppuVar6,local_480);
  pppppppWVar5 = (LPCWSTR ******)local_4b0;
  if (7 < uStack_498) {
    pppppppWVar5 = local_4b0[0];
  }
  __std_fs_get_stats((LPCWSTR)pppppppWVar5,local_470,3,0xffffffff);
  if (7 < uStack_498) {
    if ((0xfff < uStack_498 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_4b0[0] + (-8 - (longlong)local_4b0[0][-1]))))
    goto LAB_140016b6e;
    FUN_14002f180();
  }
  local_4a0 = _DAT_14006e180;
  uStack_498 = _UNK_14006e188;
  local_4b0[0] = (LPCWSTR ******)((ulonglong)local_4b0[0] & 0xffffffffffff0000);
  if (7 < local_478) {
    if ((0xfff < local_478 * 2 + 2) &&
       (0x1f < (ulonglong)((longlong)local_490[0] + (-8 - (longlong)local_490[0][-1])))) {
      FUN_140035d28();
LAB_140016b6e:
      FUN_140035d28();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    FUN_14002f180();
  }
  local_480 = 0;
  local_478 = 7;
  local_490[0] = (undefined8 *******)((ulonglong)local_490[0] & 0xffffffffffff0000);
  FUN_140015270((longlong)&local_448);
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_508);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016b80 @ 140016b80