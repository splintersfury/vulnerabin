void FUN_140004110(DWORD *param_1,undefined8 param_2,void *param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  HCRYPTMSG pvVar3;
  HCRYPTMSG pvVar4;
  longlong *in_stack_00000038;
  undefined1 auStackY_a8 [32];
  HCERTSTORE local_48;
  HCRYPTMSG local_40;
  undefined **ppuStack_38;
  DWORD local_2c;
  DWORD local_28 [2];
  DWORD local_20 [2];
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStackY_a8;
  local_48 = (HCRYPTMSG)0x0;
  local_40 = (HCRYPTMSG)0x0;
  BVar1 = CryptQueryObject(1,param_3,0x400,2,0,&local_2c,local_28,local_20,&local_48,&local_40,
                           (void **)0x0);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    local_40 = (HCRYPTMSG)CONCAT44(local_40._4_4_,DVar2);
    ppuStack_38 = &PTR_vftable_14007ad08;
    *in_stack_00000038 = (longlong)local_40;
    in_stack_00000038[1] = (longlong)&PTR_vftable_14007ad08;
    param_1[0] = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    param_1[7] = 0;
    *(code **)(param_1 + 8) = CertFreeCertificateContext_exref;
    param_1[10] = 0;
    param_1[0xb] = 0;
    *(code **)(param_1 + 0xc) = CertFreeCRLContext_exref;
    param_1[0xe] = 0;
    param_1[0xf] = 0;
    *(code **)(param_1 + 0x10) = CertFreeCTLContext_exref;
    param_1[0x12] = 0;
    param_1[0x13] = 0;
  }
  else {
    *(undefined4 *)in_stack_00000038 = 0;
    in_stack_00000038[1] = (longlong)&PTR_vftable_14007ac70;
    pvVar3 = (HCRYPTMSG)0x0;
    if (local_48 != (HCRYPTMSG)0x0) {
      pvVar3 = local_48;
    }
    pvVar4 = (HCRYPTMSG)0x0;
    if (local_40 != (HCRYPTMSG)0x0) {
      pvVar4 = local_40;
    }
    *param_1 = local_2c;
    param_1[1] = local_28[0];
    param_1[2] = local_20[0];
    *(HCRYPTMSG *)(param_1 + 4) = pvVar3;
    *(HCRYPTMSG *)(param_1 + 6) = pvVar4;
    *(code **)(param_1 + 8) = CertFreeCertificateContext_exref;
    param_1[10] = 0;
    param_1[0xb] = 0;
    *(code **)(param_1 + 0xc) = CertFreeCRLContext_exref;
    param_1[0xe] = 0;
    param_1[0xf] = 0;
    *(code **)(param_1 + 0x10) = CertFreeCTLContext_exref;
    param_1[0x12] = 0;
    param_1[0x13] = 0;
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStackY_a8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400042c0 @ 1400042c0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */