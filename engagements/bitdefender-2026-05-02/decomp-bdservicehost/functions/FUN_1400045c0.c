void FUN_1400045c0(ulonglong *param_1,undefined8 param_2,int *param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  DWORD DVar3;
  PCCERT_CONTEXT pCVar4;
  longlong *plVar5;
  undefined **ppuVar6;
  undefined **ppuVar7;
  PCCERT_CONTEXT pCVar8;
  undefined1 auStackY_258 [32];
  undefined4 uStack_214;
  longlong local_208;
  BYTE *pBStack_200;
  undefined8 local_1f8;
  PCERT_INFO p_Stack_1f0;
  BYTE *local_1e8;
  undefined8 uStack_1e0;
  BYTE *local_1d8;
  undefined8 uStack_1d0;
  PCERT_INFO local_1c8;
  HCERTSTORE pvStack_1c0;
  undefined8 local_1b8;
  BYTE *pBStack_1b0;
  undefined8 local_1a8;
  PCERT_INFO p_Stack_1a0;
  HCERTSTORE local_198;
  undefined8 uStack_190;
  BYTE *local_188;
  DWORD local_178;
  uint local_174 [3];
  DWORD local_168 [4];
  HCERTSTORE local_158;
  HCRYPTMSG local_150;
  longlong local_140;
  longlong local_130;
  longlong local_120;
  ulonglong local_118;
  PCERT_INFO p_Stack_110;
  BYTE *pBStack_108;
  ulonglong uStack_100;
  ulonglong local_f8;
  ulonglong uStack_f0;
  BYTE *local_e8;
  ulonglong uStack_e0;
  ulonglong local_d8;
  ulonglong uStack_d0;
  BYTE *local_c8;
  ulonglong uStack_c0;
  ulonglong local_b8;
  ulonglong uStack_b0;
  BYTE *local_a8;
  ulonglong uStack_a0;
  ulonglong local_98;
  ulonglong uStack_90;
  BYTE *local_88;
  ulonglong uStack_80;
  ulonglong local_78;
  ulonglong uStack_70;
  BYTE *local_68;
  ulonglong uStack_60;
  ulonglong local_58;
  ulonglong uStack_50;
  ulonglong local_48;
  
  local_48 = DAT_14007a060 ^ (ulonglong)auStackY_258;
  FUN_140004110(local_168,param_2,(void *)param_2);
  if ((*(undefined **)(*(longlong *)(param_3 + 2) + 8) == DAT_14007ac78) && (*param_3 == 0)) {
    pCVar8 = (PCCERT_CONTEXT)0x0;
    DVar3 = 0;
    local_178 = 0;
    BVar1 = CryptMsgGetParam(local_150,6,0,(void *)0x0,&local_178);
    ppuVar7 = &PTR_vftable_14007ac70;
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      *(ulonglong *)param_3 = CONCAT44(uStack_214,DVar2);
      *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ad08;
      ppuVar6 = *(undefined ***)(param_3 + 2);
    }
    else {
      *param_3 = 0;
      *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ac70;
      ppuVar6 = &PTR_vftable_14007ac70;
      DVar3 = local_178;
    }
    pCVar4 = pCVar8;
    if (((ppuVar6[1] == DAT_14007ac78) && (*param_3 == 0)) && (DVar3 != 0)) {
      pCVar4 = (PCCERT_CONTEXT)thunk_FUN_14002fe08((ulonglong)DVar3);
      if (pCVar4 == (PCCERT_CONTEXT)0x0) {
        *(ulonglong *)param_3 = CONCAT44(uStack_214,8);
        *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ad08;
        pCVar4 = pCVar8;
      }
      else {
        local_174[0] = DVar3;
        BVar1 = CryptMsgGetParam(local_150,6,0,pCVar4,local_174);
        if (BVar1 == 0) {
          DVar3 = GetLastError();
          *(ulonglong *)param_3 = CONCAT44(uStack_214,DVar3);
          *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ad08;
          ppuVar6 = *(undefined ***)(param_3 + 2);
        }
        else {
          *param_3 = 0;
          *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ac70;
          ppuVar6 = &PTR_vftable_14007ac70;
        }
        if ((ppuVar6[1] != DAT_14007ac78) || (*param_3 != 0)) {
          FUN_14002f180();
          pCVar4 = pCVar8;
        }
      }
    }
    if ((*(undefined **)(*(longlong *)(param_3 + 2) + 8) == DAT_14007ac78) && (*param_3 == 0)) {
      FUN_140031e00((undefined1 (*) [16])&local_118,0,0xd0);
      local_e8 = pCVar4->pbCertEncoded;
      uStack_e0 = *(ulonglong *)&pCVar4->cbCertEncoded;
      local_208 = *(longlong *)pCVar4;
      pBStack_200 = pCVar4->pbCertEncoded;
      local_1f8 = *(undefined8 *)&pCVar4->cbCertEncoded;
      p_Stack_1f0 = pCVar4->pCertInfo;
      local_1e8 = (BYTE *)pCVar4->hCertStore;
      uStack_1e0 = *(undefined8 *)(pCVar4 + 1);
      local_1d8 = pCVar4[1].pbCertEncoded;
      uStack_1d0 = *(undefined8 *)&pCVar4[1].cbCertEncoded;
      local_1c8 = pCVar4[1].pCertInfo;
      pvStack_1c0 = pCVar4[1].hCertStore;
      local_1b8 = *(undefined8 *)(pCVar4 + 2);
      pBStack_1b0 = pCVar4[2].pbCertEncoded;
      local_1a8 = *(undefined8 *)&pCVar4[2].cbCertEncoded;
      p_Stack_1a0 = pCVar4[2].pCertInfo;
      local_198 = pCVar4[2].hCertStore;
      uStack_190 = *(undefined8 *)(pCVar4 + 3);
      local_188 = pCVar4[3].pbCertEncoded;
      p_Stack_110 = p_Stack_1f0;
      pBStack_108 = local_1e8;
      pCVar4 = CertFindCertificateInStore
                         (local_158,0x10001,0,0xb0000,&local_118,(PCCERT_CONTEXT)0x0);
      if ((pCVar4 == (PCCERT_CONTEXT)0x0) && (DVar3 = GetLastError(), DVar3 != 0x80092004)) {
        *(ulonglong *)param_3 = CONCAT44(uStack_214,DVar3);
        *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ad08;
        ppuVar7 = *(undefined ***)(param_3 + 2);
        pCVar4 = pCVar8;
      }
      else {
        *param_3 = 0;
        *(undefined ***)(param_3 + 2) = &PTR_vftable_14007ac70;
      }
      if ((ppuVar7[1] == DAT_14007ac78) && (*param_3 == 0)) {
        local_118 = 0;
        pBStack_108 = _DAT_14006e180;
        uStack_100 = _UNK_14006e188;
        local_f8 = 0;
        local_e8 = _DAT_14006e180;
        uStack_e0 = _UNK_14006e188;
        local_d8 = 0;
        local_c8 = _DAT_14006e180;
        uStack_c0 = _UNK_14006e188;
        local_b8 = 0;
        local_a8 = _DAT_14006e180;
        uStack_a0 = _UNK_14006e188;
        local_98 = 0;
        local_88 = _DAT_14006e180;
        uStack_80 = _UNK_14006e188;
        local_78 = 0;
        local_68 = _DAT_14006e180;
        uStack_60 = _UNK_14006e188;
        local_58 = 0;
        uStack_50 = 0;
        plVar5 = (longlong *)FUN_1400042c0(&local_208,pCVar4,param_3);
        FUN_14000e6b0((longlong *)&local_118,plVar5);
        FUN_14000e6b0((longlong *)&local_f8,plVar5 + 4);
        FUN_14000e6b0((longlong *)&local_d8,plVar5 + 8);
        FUN_1400039f0(&local_208);
        if ((*(undefined **)(*(longlong *)(param_3 + 2) + 8) == DAT_14007ac78) && (*param_3 == 0)) {
          *param_1 = local_118;
          param_1[1] = (ulonglong)p_Stack_110;
          param_1[2] = (ulonglong)pBStack_108;
          param_1[3] = uStack_100;
          pBStack_108 = _DAT_14006e180;
          uStack_100 = _UNK_14006e188;
          local_118 = local_118 & 0xffffffffffff0000;
          param_1[4] = local_f8;
          param_1[5] = uStack_f0;
          param_1[6] = (ulonglong)local_e8;
          param_1[7] = uStack_e0;
          local_e8 = _DAT_14006e180;
          uStack_e0 = _UNK_14006e188;
          local_f8 = local_f8 & 0xffffffffffff0000;
          param_1[8] = local_d8;
          param_1[9] = uStack_d0;
          param_1[10] = (ulonglong)local_c8;
          param_1[0xb] = uStack_c0;
          local_c8 = _DAT_14006e180;
          uStack_c0 = _UNK_14006e188;
          local_d8 = local_d8 & 0xffffffffffff0000;
          param_1[0xc] = local_b8;
          param_1[0xd] = uStack_b0;
          param_1[0xe] = (ulonglong)local_a8;
          param_1[0xf] = uStack_a0;
          local_a8 = _DAT_14006e180;
          uStack_a0 = _UNK_14006e188;
          local_b8 = local_b8 & 0xffffffffffff0000;
          param_1[0x10] = local_98;
          param_1[0x11] = uStack_90;
          param_1[0x12] = (ulonglong)local_88;
          param_1[0x13] = uStack_80;
          local_88 = _DAT_14006e180;
          uStack_80 = _UNK_14006e188;
          local_98 = local_98 & 0xffffffffffff0000;
          param_1[0x14] = local_78;
          param_1[0x15] = uStack_70;
          param_1[0x16] = (ulonglong)local_68;
          param_1[0x17] = uStack_60;
          local_68 = _DAT_14006e180;
          uStack_60 = _UNK_14006e188;
          local_78 = local_78 & 0xffffffffffff0000;
          param_1[0x18] = local_58;
          param_1[0x19] = uStack_50;
          FUN_1400039f0((longlong *)&local_b8);
          FUN_1400039f0((longlong *)&local_118);
          if (pCVar4 != (PCCERT_CONTEXT)0x0) {
            CertFreeCertificateContext(pCVar4);
          }
          FUN_14002f180();
          if (local_120 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
          if (local_130 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
          if (local_140 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
        }
        else {
          *param_1 = 0;
          param_1[2] = 0;
          param_1[3] = 7;
          param_1[4] = 0;
          param_1[6] = 0;
          param_1[7] = 7;
          param_1[8] = 0;
          param_1[10] = 0;
          param_1[0xb] = 7;
          param_1[0xc] = 0;
          param_1[0xe] = 0;
          param_1[0xf] = 7;
          param_1[0x10] = 0;
          param_1[0x12] = 0;
          param_1[0x13] = 7;
          param_1[0x14] = 0;
          param_1[0x16] = 0;
          param_1[0x17] = 7;
          param_1[0x18] = 0;
          param_1[0x19] = 0;
          FUN_1400039f0((longlong *)&local_b8);
          FUN_1400039f0((longlong *)&local_118);
          if (pCVar4 != (PCCERT_CONTEXT)0x0) {
            CertFreeCertificateContext(pCVar4);
          }
          FUN_14002f180();
          if (local_120 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
          if (local_130 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
          if (local_140 != 0) {
            (*(code *)PTR__guard_dispatch_icall_14005b538)();
          }
        }
      }
      else {
        *param_1 = 0;
        param_1[2] = 0;
        param_1[3] = 7;
        param_1[4] = 0;
        param_1[6] = 0;
        param_1[7] = 7;
        param_1[8] = 0;
        param_1[10] = 0;
        param_1[0xb] = 7;
        param_1[0xc] = 0;
        param_1[0xe] = 0;
        param_1[0xf] = 7;
        param_1[0x10] = 0;
        param_1[0x12] = 0;
        param_1[0x13] = 7;
        param_1[0x14] = 0;
        param_1[0x16] = 0;
        param_1[0x17] = 7;
        param_1[0x18] = 0;
        param_1[0x19] = 0;
        if (pCVar4 != (PCCERT_CONTEXT)0x0) {
          CertFreeCertificateContext(pCVar4);
        }
        FUN_14002f180();
        if (local_120 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (local_130 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (local_140 != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
      }
    }
    else {
      *param_1 = 0;
      param_1[2] = 0;
      param_1[3] = 7;
      param_1[4] = 0;
      param_1[6] = 0;
      param_1[7] = 7;
      param_1[8] = 0;
      param_1[10] = 0;
      param_1[0xb] = 7;
      param_1[0xc] = 0;
      param_1[0xe] = 0;
      param_1[0xf] = 7;
      param_1[0x10] = 0;
      param_1[0x12] = 0;
      param_1[0x13] = 7;
      param_1[0x14] = 0;
      param_1[0x16] = 0;
      param_1[0x17] = 7;
      param_1[0x18] = 0;
      param_1[0x19] = 0;
      if (pCVar4 != (PCCERT_CONTEXT)0x0) {
        FUN_14002f180();
      }
      if (local_120 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)();
      }
      if (local_130 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)();
      }
      if (local_140 != 0) {
        (*(code *)PTR__guard_dispatch_icall_14005b538)();
      }
    }
  }
  else {
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 7;
    param_1[4] = 0;
    param_1[6] = 0;
    param_1[7] = 7;
    param_1[8] = 0;
    param_1[10] = 0;
    param_1[0xb] = 7;
    param_1[0xc] = 0;
    param_1[0xe] = 0;
    param_1[0xf] = 7;
    param_1[0x10] = 0;
    param_1[0x12] = 0;
    param_1[0x13] = 7;
    param_1[0x14] = 0;
    param_1[0x16] = 0;
    param_1[0x17] = 7;
    param_1[0x18] = 0;
    param_1[0x19] = 0;
    if (local_120 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
    if (local_130 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
    if (local_140 != 0) {
      (*(code *)PTR__guard_dispatch_icall_14005b538)();
    }
  }
  if (local_150 != (HCRYPTMSG)0x0) {
    CryptMsgClose(local_150);
  }
  if (local_158 != (HCERTSTORE)0x0) {
    CertCloseStore(local_158,0);
  }
  FUN_14002f160(local_48 ^ (ulonglong)auStackY_258);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140004ee0 @ 140004ee0