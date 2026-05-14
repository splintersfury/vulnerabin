void FUN_140005250(LPCWSTR param_1,DWORD *param_2)

{
  bool bVar1;
  ulong uVar2;
  undefined **ppuVar3;
  undefined1 auStack_d8 [32];
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 *local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_58;
  LPCWSTR local_50;
  undefined8 local_48;
  undefined8 uStack_40;
  GUID local_38;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_d8;
  local_88 = 0;
  local_68 = 0;
  local_90 = &local_58;
  local_58 = 0x20;
  local_b8 = 0x58;
  local_98 = 1;
  local_b0 = 0;
  local_a8 = 0;
  local_48 = 0;
  uStack_40 = 0;
  local_a0 = 2;
  local_70 = 0x1000;
  local_80 = 0;
  local_78 = 0;
  local_38.Data1 = 0xaac56b;
  local_38.Data2 = 0xcd44;
  local_38.Data3 = 0x11d0;
  local_38.Data4[0] = 0x8c;
  local_38.Data4[1] = 0xc2;
  local_38.Data4[2] = '\0';
  local_38.Data4[3] = 0xc0;
  local_38.Data4[4] = 'O';
  local_38.Data4[5] = 0xc2;
  local_38.Data4[6] = 0x95;
  local_38.Data4[7] = 0xee;
  local_50 = param_1;
  uVar2 = WinVerifyTrust((HWND)0x0,&local_38,&local_b8);
  if (uVar2 == 0) {
    ppuVar3 = &PTR_vftable_14007ac70;
    *param_2 = 0;
    *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
    bVar1 = true;
  }
  else {
    bVar1 = false;
    if (uVar2 == 0x800b0004) {
      ppuVar3 = &PTR_vftable_14007ac70;
      *param_2 = 0;
      *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ac70;
    }
    else {
      local_38.Data4 = (uchar  [8])&PTR_vftable_14007ad08;
      *(ulonglong *)param_2 = CONCAT44(local_38._4_4_,uVar2);
      *(undefined ***)(param_2 + 2) = &PTR_vftable_14007ad08;
      ppuVar3 = *(undefined ***)(param_2 + 2);
      local_38.Data1 = uVar2;
    }
  }
  if (((ppuVar3[1] != DAT_14007ac78) || (*param_2 != 0)) || (!bVar1)) {
    FUN_140004ee0(param_1,param_2);
  }
  FUN_14002f160(local_28 ^ (ulonglong)auStack_d8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140005390 @ 140005390