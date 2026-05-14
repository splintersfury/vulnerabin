void FUN_14000a330(longlong param_1)

{
  code *pcVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *******pppppppuVar4;
  LPCWSTR ******pppppppWVar5;
  LPCWSTR ******pppppppWVar6;
  undefined8 uVar7;
  undefined1 auStack_d8 [32];
  LPCWSTR ******local_b8 [2];
  undefined8 local_a8;
  ulonglong uStack_a0;
  LPCWSTR ******local_90 [3];
  ulonglong local_78;
  undefined1 local_70;
  undefined8 *******local_68 [2];
  ulonglong local_58;
  ulonglong local_50;
  char local_48;
  ulonglong local_40 [3];
  ulonglong local_28 [3];
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_d8;
  if (*(char *)(param_1 + 0x20) != '\0') {
    uVar7 = 400;
    pppppppuVar4 = local_68;
    FUN_140009170(param_1,pppppppuVar4,400,L"Desktop");
    if (local_48 != '\0') {
      puVar3 = (undefined8 *)FUN_14000a2b0(param_1,pppppppuVar4,uVar7);
      local_70 = 0;
      if (*(char *)(puVar3 + 4) != '\0') {
        FUN_14000e750(local_90,puVar3);
        local_70 = 1;
        pppppppuVar4 = local_68;
        if (7 < local_50) {
          pppppppuVar4 = local_68[0];
        }
        local_b8[0] = (LPCWSTR ******)0x0;
        local_a8 = 0;
        uStack_a0 = 7;
        FUN_140010340((longlong *)local_b8,pppppppuVar4,local_58);
        pppppppWVar6 = (LPCWSTR ******)local_90;
        if (7 < local_78) {
          pppppppWVar6 = local_90[0];
        }
        pppppppWVar5 = (LPCWSTR ******)local_b8;
        if (7 < uStack_a0) {
          pppppppWVar5 = local_b8[0];
        }
        iVar2 = __std_fs_get_file_id(local_40,(LPCWSTR)pppppppWVar5);
        if (iVar2 == 0) {
          __std_fs_get_file_id(local_28,(LPCWSTR)pppppppWVar6);
        }
        if (7 < uStack_a0) {
          if ((0xfff < uStack_a0 * 2 + 2) &&
             (0x1f < (ulonglong)((longlong)local_b8[0] + (-8 - (longlong)local_b8[0][-1])))) {
            FUN_140035d28();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          FUN_14002f180();
        }
        local_a8 = _DAT_14006e180;
        uStack_a0 = _UNK_14006e188;
        local_b8[0] = (LPCWSTR ******)((ulonglong)local_b8[0] & 0xffffffffffff0000);
      }
      FUN_14000d470((longlong *)local_90);
    }
    FUN_14000d470((longlong *)local_68);
  }
  FUN_14002f160(local_10 ^ (ulonglong)auStack_d8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a4d0 @ 14000a4d0