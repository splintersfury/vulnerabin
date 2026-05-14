void __fastcall
FUN_10009ff0(undefined4 *param_1,undefined4 *param_2,LPCWSTR param_3,LPCWSTR param_4,int *param_5)

{
  code *pcVar1;
  LSTATUS LVar2;
  undefined **ppuVar3;
  undefined4 ****ppppuVar4;
  undefined4 *puVar5;
  uint uVar6;
  uint uStack_68;
  undefined4 ***local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  uint local_38;
  uint uStack_34;
  undefined4 *local_30;
  uint local_2c;
  undefined1 *puStack_24;
  undefined1 *local_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e2cd;
  local_1c = ExceptionList;
  uStack_68 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  local_20 = (undefined1 *)&uStack_68;
  ExceptionList = &local_1c;
  local_30 = param_1;
  local_2c = uStack_68;
  LVar2 = RegGetValueW((HKEY)*param_2,param_3,param_4,2,(LPDWORD)0x0,(PVOID)0x0,(LPDWORD)&local_30);
  if (LVar2 == 0) {
    ppuVar3 = &PTR_vftable_10069aa8;
    *param_5 = 0;
    param_5[1] = (int)&PTR_vftable_10069aa8;
    puVar5 = local_30;
  }
  else {
    *param_5 = LVar2;
    param_5[1] = (int)&PTR_vftable_10069ab8;
    ppuVar3 = (undefined **)param_5[1];
    puVar5 = (undefined4 *)0x0;
  }
  if (((ppuVar3[1] == DAT_10069aac) && (*param_5 == 0)) && (puVar5 != (undefined4 *)0x0)) {
    local_38 = 0;
    uStack_34 = 7;
    local_48 = (undefined4 ****)0x0;
    local_14 = 1;
    if ((uint)puVar5 >> 1 == 0) {
                    /* WARNING: Ignoring partial resolution of indirect */
      local_48._0_2_ = 0;
      local_38 = 0;
    }
    else {
      FUN_1000f950(&local_48,(uint)puVar5 >> 1,0);
    }
    ppppuVar4 = &local_48;
    if (7 < uStack_34) {
      ppppuVar4 = (undefined4 ****)local_48;
    }
    local_30 = (undefined4 *)(local_38 * 2);
    LVar2 = RegGetValueW((HKEY)*param_2,param_3,param_4,2,(LPDWORD)0x0,ppppuVar4,(LPDWORD)&local_30)
    ;
    if (LVar2 == 0) {
      ppuVar3 = &PTR_vftable_10069aa8;
      *param_5 = 0;
      param_5[1] = (int)&PTR_vftable_10069aa8;
      puVar5 = local_30;
    }
    else {
      *param_5 = LVar2;
      param_5[1] = (int)&PTR_vftable_10069ab8;
      ppuVar3 = (undefined **)param_5[1];
      puVar5 = (undefined4 *)0x0;
    }
    if ((ppuVar3[1] == DAT_10069aac) && (*param_5 == 0)) {
      uVar6 = ((uint)puVar5 >> 1) - 1;
      if (local_38 < uVar6) {
        FUN_1000f950(&local_48,uVar6 - local_38,0);
      }
      else {
        ppppuVar4 = &local_48;
        if (7 < uStack_34) {
          ppppuVar4 = (undefined4 ****)local_48;
        }
        local_38 = uVar6;
        *(undefined2 *)((int)ppppuVar4 + uVar6 * 2) = 0;
      }
      FUN_1000ea80((uint *)&local_48);
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 0;
      *param_1 = local_48;
      param_1[1] = uStack_44;
      param_1[2] = uStack_40;
      param_1[3] = uStack_3c;
      *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_34,local_38);
    }
    else {
      *param_1 = 0;
      param_1[4] = 0;
      param_1[5] = 7;
      *(undefined2 *)param_1 = 0;
      if (7 < uStack_34) {
        ppppuVar4 = (undefined4 ****)local_48;
        if ((0xfff < uStack_34 * 2 + 2) &&
           (ppppuVar4 = (undefined4 ****)local_48[-1],
           0x1f < (uint)((int)local_48 + (-4 - (int)ppppuVar4)))) {
          FUN_10032f7f();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
        FUN_1002e346(ppppuVar4);
      }
    }
  }
  else {
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 7;
    *(undefined2 *)param_1 = 0;
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_2c ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1000a200 @ 1000a200