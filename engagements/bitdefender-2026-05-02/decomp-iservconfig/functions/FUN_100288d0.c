void __fastcall FUN_100288d0(undefined4 *param_1)

{
  code *pcVar1;
  undefined **ppuVar2;
  undefined4 ****ppppuVar3;
  uint uVar4;
  HKEY hkey;
  int local_f8 [24];
  undefined **local_98 [18];
  int *local_50;
  int *local_4c;
  HKEY local_48;
  HKEY local_44;
  undefined4 ***local_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  uint local_30;
  uint uStack_2c;
  int *local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_10050711;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_48 = (HKEY)0x0;
  local_4c = param_1;
  local_50 = (int *)RegOpenKeyExW((HKEY)0x80000002,L"SOFTWARE\\Microsoft\\Cryptography",0,0x20119,
                                  &local_48);
  if (local_50 == (int *)0x0) {
    local_50 = (int *)0x0;
    ppuVar2 = &PTR_vftable_10069aa8;
    hkey = local_48;
  }
  else {
    ppuVar2 = &PTR_vftable_10069ab8;
    hkey = (HKEY)0x0;
  }
  local_14 = 0;
  local_44 = hkey;
  if ((ppuVar2[1] == DAT_10069aac) && (local_50 == (int *)0x0)) {
    local_28 = local_50;
    local_4c = (int *)RegGetValueW(hkey,(LPCWSTR)0x0,L"MachineGuid",2,(LPDWORD)0x0,(PVOID)0x0,
                                   (LPDWORD)&local_28);
    if (local_4c == (int *)0x0) {
      if (((uint)local_28 & 1) == 0) {
        local_30 = 0;
        uStack_2c = 7;
        local_40 = (undefined4 ****)0x0;
        local_14._0_1_ = 7;
        if ((uint)local_28 >> 1 == 0) {
                    /* WARNING: Ignoring partial resolution of indirect */
          local_40._0_2_ = 0;
          local_30 = 0;
        }
        else {
          FUN_1000f950(&local_40,(uint)local_28 >> 1,0);
        }
        ppppuVar3 = &local_40;
        if (7 < uStack_2c) {
          ppppuVar3 = (undefined4 ****)local_40;
        }
        local_50 = (int *)RegGetValueW(hkey,(LPCWSTR)0x0,L"MachineGuid",2,(LPDWORD)0x0,ppppuVar3,
                                       (LPDWORD)&local_28);
        if (local_50 == (int *)0x0) {
          uVar4 = ((uint)local_28 >> 1) - 1;
          if (local_30 < uVar4) {
            FUN_1000f950(&local_40,uVar4 - local_30,0);
          }
          else {
            ppppuVar3 = &local_40;
            if (7 < uStack_2c) {
              ppppuVar3 = (undefined4 ****)local_40;
            }
            local_30 = uVar4;
            *(undefined2 *)((int)ppppuVar3 + uVar4 * 2) = 0;
          }
          FUN_1000ea80((uint *)&local_40);
          *param_1 = 0;
          param_1[4] = 0;
          param_1[5] = 0;
          *param_1 = local_40;
          param_1[1] = uStack_3c;
          param_1[2] = uStack_38;
          param_1[3] = uStack_34;
          local_40 = (undefined4 ***)((uint)local_40 & 0xffff0000);
          *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_2c,local_30);
          local_30 = 0;
          uStack_2c = 7;
        }
        else {
          local_4c = FUN_100034b0(local_f8,4,0x100612ac);
          local_14._0_1_ = 8;
          if ((char)local_4c[0x12] != '\0') {
            FUN_100082c0(local_4c,L"RegGetValue failed err=");
            if ((char)local_4c[0x12] != '\0') {
              FUN_1002b5f0(local_4c,local_50);
            }
          }
          FUN_10003240((int)local_98);
          local_14._0_1_ = 9;
          local_98[0] = std::ios_base::vftable;
          std::ios_base::_Ios_base_dtor((ios_base *)local_98);
          *param_1 = 0;
          param_1[4] = 0;
          param_1[5] = 7;
          *(undefined2 *)param_1 = 0;
          if (7 < uStack_2c) {
            ppppuVar3 = (undefined4 ****)local_40;
            if (0xfff < uStack_2c * 2 + 2) {
              ppppuVar3 = (undefined4 ****)local_40[-1];
              if (0x1f < (uint)((int)local_40 + (-4 - (int)ppppuVar3))) {
                FUN_10032f7f();
                pcVar1 = (code *)swi(3);
                (*pcVar1)();
                return;
              }
            }
            FUN_1002e346(ppppuVar3);
          }
          local_30 = 0;
          uStack_2c = 7;
          local_40 = (undefined4 ***)((uint)local_40 & 0xffff0000);
        }
        goto LAB_10028c91;
      }
      local_4c = FUN_100034b0(local_f8,4,0x100612ac);
      local_14._0_1_ = 5;
      if ((char)local_4c[0x12] != '\0') {
        FUN_100082c0(local_4c,L"unexpected size=");
        if ((char)local_4c[0x12] != '\0') {
          FUN_10027670(local_4c,local_28);
        }
      }
      FUN_10003240((int)local_98);
      local_14._0_1_ = 6;
    }
    else {
      local_50 = FUN_100034b0(local_f8,4,0x100612ac);
      local_14._0_1_ = 3;
      if ((char)local_50[0x12] != '\0') {
        FUN_100082c0(local_50,L"RegGetValue for size failed err=");
        if ((char)local_50[0x12] != '\0') {
          FUN_1002b5f0(local_50,local_4c);
        }
      }
      FUN_10003240((int)local_98);
      local_14._0_1_ = 4;
    }
  }
  else {
    local_4c = FUN_100034b0(local_f8,4,0x100612ac);
    local_14._0_1_ = 1;
    if ((char)local_4c[0x12] != '\0') {
      FUN_100082c0(local_4c,L"reg open HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography err=");
      if ((char)local_4c[0x12] != '\0') {
        FUN_10006730(local_4c,local_50);
      }
    }
    FUN_10003240((int)local_98);
    local_14._0_1_ = 2;
  }
  local_98[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_98);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
LAB_10028c91:
  if (hkey != (HKEY)0x0) {
    RegCloseKey(hkey);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10028cd0 @ 10028cd0