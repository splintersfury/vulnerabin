void FUN_10002dd0(uint *param_1,uint param_2)

{
  code *pcVar1;
  LPSTR ******pppppppCVar2;
  DWORD DVar3;
  void *pvVar4;
  uint *puVar5;
  void *local_74 [4];
  undefined4 local_64;
  uint local_60;
  uint *local_5c;
  uint local_58;
  LPSTR ******local_54;
  uint uStack_50;
  uint uStack_4c;
  uint uStack_48;
  undefined4 local_44;
  uint uStack_40;
  undefined1 local_28 [4];
  uint local_24 [3];
  undefined2 local_18;
  undefined1 local_16;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dab5;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_5c = param_1;
  local_58 = param_2;
  local_44 = 0;
  uStack_40 = 0xf;
  local_54 = (LPSTR ******)0x0;
  FUN_10008d00(&local_54,0x7fff,'\0');
  local_8 = 0;
  pppppppCVar2 = (LPSTR ******)&local_54;
  if (0xf < uStack_40) {
    pppppppCVar2 = local_54;
  }
  DVar3 = FormatMessageA(0x1200,(LPCVOID)0x0,param_2,0,(LPSTR)pppppppCVar2,0x7fff,(va_list *)0x0);
  if (DVar3 == 0) {
    local_24[0] = 0x6e6b6e75;
    puVar5 = (uint *)((int)local_28 + 1);
    local_24[1] = 0x206e776f;
    local_24[2] = 0x6f727265;
    local_18 = 0x2072;
    local_16 = 0;
    do {
      puVar5 = (uint *)((int)puVar5 + -1);
      param_2 = param_2 / 10;
      *(char *)puVar5 = (char)local_58 + (char)param_2 * -10 + '0';
      local_58 = param_2;
    } while (param_2 != 0);
    local_64 = 0;
    local_60 = 0xf;
    local_74[0] = (void *)0x0;
    if (puVar5 != (uint *)((int)local_28 + 1U)) {
      FUN_10008e70(local_74,puVar5,((int)local_28 + 1U) - (int)puVar5);
    }
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_10005f20(local_5c,local_24,(uint *)local_74);
    if (0xf < local_60) {
      pvVar4 = local_74[0];
      if ((0xfff < local_60 + 1) &&
         (pvVar4 = *(void **)((int)local_74[0] + -4),
         0x1f < (uint)((int)local_74[0] + (-4 - (int)pvVar4)))) goto LAB_10002fc2;
      FUN_1002e346(pvVar4);
    }
    local_64 = 0;
    local_60 = 0xf;
    local_74[0] = (void *)((uint)local_74[0] & 0xffffff00);
    if (0xf < uStack_40) {
      pppppppCVar2 = local_54;
      if ((0xfff < uStack_40 + 1) &&
         (pppppppCVar2 = (LPSTR ******)local_54[-1],
         (LPSTR)0x1f < (LPSTR)((int)local_54 + (-4 - (int)pppppppCVar2)))) {
LAB_10002fc2:
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      FUN_1002e346(pppppppCVar2);
    }
  }
  else {
    FUN_10005410(&local_54,DVar3,'\0');
    FUN_10005490((uint *)&local_54);
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    *param_1 = (uint)local_54;
    param_1[1] = uStack_50;
    param_1[2] = uStack_4c;
    param_1[3] = uStack_48;
    *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_40,local_44);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002fd0 @ 10002fd0