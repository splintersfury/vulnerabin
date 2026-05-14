void FUN_14001a7f0(float *param_1,byte *param_2)

{
  undefined8 *****pppppuVar1;
  byte bVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  longlong *plVar7;
  float *pfVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  longlong *plVar11;
  int iVar12;
  void *pvVar13;
  undefined8 *puVar14;
  undefined **ppuVar15;
  longlong *plVar16;
  char *pcVar17;
  undefined8 *puVar18;
  undefined8 *puVar19;
  byte *pbVar20;
  byte *pbVar21;
  longlong *****_Buf1;
  longlong lVar22;
  undefined8 *****pppppuVar23;
  longlong lVar24;
  byte *pbVar25;
  ulonglong uVar26;
  ulonglong uVar27;
  longlong *****ppppplVar28;
  uint uVar29;
  size_t sVar30;
  longlong lVar31;
  uint uVar32;
  longlong *plVar33;
  char cVar34;
  bool bVar35;
  undefined1 auStack_1b8 [32];
  char local_198;
  uint local_194;
  byte *local_190;
  longlong ****local_188;
  uint local_180;
  undefined8 *local_178;
  float *local_170;
  longlong local_168 [7];
  undefined8 local_130 [7];
  float *local_f8;
  longlong local_f0;
  undefined8 *local_e8;
  longlong local_d0 [3];
  longlong ****local_b8;
  undefined8 local_b0;
  ulonglong uStack_a8;
  ulonglong local_a0;
  float local_98 [2];
  void *pvStack_90;
  undefined8 local_88;
  ulonglong uStack_80;
  undefined8 local_78;
  undefined8 uStack_70;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 ****local_58 [2];
  undefined8 local_48;
  ulonglong local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_1b8;
  local_194 = 0;
  local_180 = 0;
  uStack_80 = 0;
  local_78 = 0;
  uStack_70 = 0;
  local_68 = 0;
  uStack_60 = 0;
  local_98[0] = 0.0;
  local_98[1] = 0.0;
  pvStack_90 = (void *)0x0;
  local_88 = 0;
  local_190 = param_2;
  local_170 = param_1;
  local_f8 = param_1;
  pvStack_90 = operator_new(0x20);
  *(void **)pvStack_90 = pvStack_90;
  *(void **)((longlong)pvStack_90 + 8) = pvStack_90;
  uStack_80 = 0;
  local_78 = 0;
  uStack_70 = 0;
  local_68 = 7;
  uStack_60 = 8;
  local_98[0] = (float)DAT_14006e158;
  FUN_140016fb0(&uStack_80,0x10,pvStack_90);
  local_b0 = 0;
  uStack_a8 = 0;
  local_a0 = 0;
  lVar31 = -0x8000000000000000;
  lVar24 = -0x8000000000000000;
  uVar32 = (uint)*local_190;
  uVar29 = (uint)*local_190;
  local_188 = (longlong ****)CONCAT44(local_188._4_4_,uVar29);
  if (uVar29 == 1) {
LAB_14001a912:
    puVar18 = (undefined8 *)**(undefined8 **)(local_190 + 8);
LAB_14001a919:
    pbVar25 = (byte *)0x0;
  }
  else {
    if (uVar29 != 2) {
      if (uVar32 == 1) goto LAB_14001a912;
      if (uVar32 == 2) goto LAB_14001a904;
      lVar24 = 1;
      puVar18 = (undefined8 *)0x0;
      goto LAB_14001a919;
    }
LAB_14001a904:
    pbVar25 = *(byte **)(*(longlong *)(local_190 + 8) + 8);
    puVar18 = (undefined8 *)0x0;
  }
  if (*local_190 != 1) goto LAB_14001a9f1;
  puVar18 = (undefined8 *)**(longlong **)(local_190 + 8);
  puVar14 = (undefined8 *)puVar18[1];
  local_178 = puVar18;
  if (*(char *)((longlong)puVar14 + 0x19) == '\0') {
    do {
      puVar19 = puVar14 + 4;
      uVar27 = puVar14[6];
      if (0xf < (ulonglong)puVar14[7]) {
        puVar19 = (undefined8 *)*puVar19;
      }
      uVar26 = uVar27;
      if (0x10 < uVar27) {
        uVar26 = 0x10;
      }
      iVar12 = memcmp(puVar19,"registeredEvents",uVar26);
      if (iVar12 == 0) {
        if (0xf < uVar27) goto LAB_14001a97d;
LAB_14001a9d5:
        puVar19 = (undefined8 *)puVar14[2];
      }
      else {
        if (iVar12 < 0) goto LAB_14001a9d5;
LAB_14001a97d:
        puVar19 = (undefined8 *)*puVar14;
        puVar18 = puVar14;
      }
      puVar14 = puVar19;
    } while (*(char *)((longlong)puVar19 + 0x19) == '\0');
    uVar32 = (uint)local_188;
  }
  puVar14 = local_178;
  if (*(char *)((longlong)puVar18 + 0x19) == '\0') {
    puVar19 = puVar18 + 4;
    uVar27 = puVar18[6];
    if (0xf < (ulonglong)puVar18[7]) {
      puVar19 = (undefined8 *)*puVar19;
    }
    uVar26 = uVar27;
    if (0x10 < uVar27) {
      uVar26 = 0x10;
    }
    iVar12 = memcmp(puVar19,"registeredEvents",uVar26);
    param_1 = local_170;
    if (iVar12 == 0) {
      if (0x10 < uVar27) goto LAB_14001a9e1;
    }
    else if (0 < iVar12) goto LAB_14001a9e1;
  }
  else {
LAB_14001a9e1:
    puVar18 = puVar14;
    param_1 = local_170;
  }
LAB_14001a9f1:
  local_b0 = 0;
  uStack_a8 = 0;
  local_a0 = 0;
  lVar22 = -0x8000000000000000;
  bVar2 = *local_190;
  if (bVar2 == 1) {
LAB_14001aa3a:
    puVar14 = (undefined8 *)**(undefined8 **)(local_190 + 8);
LAB_14001aa41:
    pbVar20 = (byte *)0x0;
  }
  else {
    if (bVar2 != 2) {
      if (bVar2 == 1) goto LAB_14001aa3a;
      if (bVar2 == 2) goto LAB_14001aa2c;
      lVar22 = 1;
      puVar14 = (undefined8 *)0x0;
      goto LAB_14001aa41;
    }
LAB_14001aa2c:
    pbVar20 = *(byte **)(*(longlong *)(local_190 + 8) + 8);
    puVar14 = (undefined8 *)0x0;
  }
  uVar29 = uVar32 - 1;
  uVar27 = (ulonglong)uVar29;
  if (uVar29 == 0) {
    bVar35 = puVar18 == puVar14;
  }
  else if (uVar29 == 1) {
    bVar35 = pbVar25 == pbVar20;
  }
  else {
    bVar35 = lVar24 == lVar22;
  }
  if (bVar35) {
    *param_1 = local_98[0];
    param_1[2] = 0.0;
    param_1[3] = 0.0;
    param_1[4] = 0.0;
    param_1[5] = 0.0;
    pvVar13 = operator_new(0x20);
    *(void **)pvVar13 = pvVar13;
    *(void **)((longlong)pvVar13 + 8) = pvVar13;
    *(void **)(param_1 + 2) = pvVar13;
    param_1[6] = 0.0;
    param_1[7] = 0.0;
    param_1[8] = 0.0;
    param_1[9] = 0.0;
    param_1[10] = 0.0;
    param_1[0xb] = 0.0;
    FUN_140016fb0((ulonglong *)(param_1 + 6),0x10,*(undefined8 *)(param_1 + 2));
    uVar10 = uStack_60;
    uVar9 = local_68;
    uVar3 = *(undefined8 *)(param_1 + 2);
    *(void **)(param_1 + 2) = pvStack_90;
    uVar4 = *(undefined8 *)(param_1 + 4);
    *(undefined8 *)(param_1 + 4) = local_88;
    uVar27 = *(ulonglong *)(param_1 + 6);
    *(ulonglong *)(param_1 + 6) = uStack_80;
    uVar5 = *(undefined8 *)(param_1 + 8);
    *(undefined8 *)(param_1 + 8) = local_78;
    uVar6 = *(undefined8 *)(param_1 + 10);
    *(undefined8 *)(param_1 + 10) = uStack_70;
    local_68 = 7;
    *(undefined8 *)(param_1 + 0xc) = uVar9;
    uStack_60 = 8;
    *(undefined8 *)(param_1 + 0xe) = uVar10;
    pvStack_90 = (void *)uVar3;
    local_88 = uVar4;
    uStack_80 = uVar27;
    local_78 = uVar5;
    uStack_70 = uVar6;
    FUN_140010a90((longlong)local_98);
LAB_14001ab29:
    FUN_14002f160(local_38 ^ (ulonglong)auStack_1b8);
    return;
  }
  if (uVar32 == 0) {
    FUN_14000e950((longlong *)&local_b8,(undefined8 *)"cannot get value");
    FUN_140018ed0(local_130,0xd6,&local_b8);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_130,(ThrowInfo *)&DAT_140077d70);
  }
  if (uVar32 == 1) {
    pbVar25 = (byte *)(puVar18 + 8);
  }
  else if ((uVar32 != 2) && (pbVar25 = local_190, lVar24 != 0)) {
    FUN_14000e950((longlong *)&local_b8,(undefined8 *)"cannot get value");
    FUN_140018ed0(local_168,0xd6,&local_b8);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_168,(ThrowInfo *)&DAT_140077d70);
  }
  local_190 = pbVar25;
  lVar24 = -0x8000000000000000;
  bVar2 = *local_190;
  if (bVar2 == 1) {
LAB_14001abde:
    plVar16 = *(longlong **)**(undefined8 **)(local_190 + 8);
LAB_14001abeb:
    pbVar25 = (byte *)0x0;
  }
  else {
    if (bVar2 != 2) {
      if (bVar2 == 0) {
        lVar24 = 1;
        plVar16 = (longlong *)0x0;
      }
      else {
        if (bVar2 == 1) goto LAB_14001abde;
        if (bVar2 == 2) goto LAB_14001abce;
        lVar24 = 0;
        plVar16 = (longlong *)0x0;
      }
      goto LAB_14001abeb;
    }
LAB_14001abce:
    pbVar25 = (byte *)**(undefined8 **)(local_190 + 8);
    plVar16 = (longlong *)0x0;
  }
  local_b0 = 0;
  uStack_a8 = 0;
  local_a0 = 0;
  bVar2 = *local_190;
  uVar32 = local_194;
  if (bVar2 == 1) {
LAB_14001ac2d:
    plVar33 = (longlong *)**(undefined8 **)(local_190 + 8);
  }
  else {
    if (bVar2 == 2) {
LAB_14001ac1f:
      pbVar20 = *(byte **)(*(longlong *)(local_190 + 8) + 8);
      plVar33 = (longlong *)0x0;
      goto LAB_14001ac40;
    }
    if (bVar2 == 1) goto LAB_14001ac2d;
    if (bVar2 == 2) goto LAB_14001ac1f;
    lVar31 = 1;
    plVar33 = (longlong *)0x0;
  }
  pbVar20 = (byte *)0x0;
LAB_14001ac40:
  do {
    pfVar8 = local_170;
    bVar2 = *local_190;
    if (bVar2 == 1) {
      bVar35 = plVar16 == plVar33;
    }
    else if (bVar2 == 2) {
      bVar35 = pbVar25 == pbVar20;
    }
    else {
      bVar35 = lVar24 == lVar31;
    }
    if (bVar35) {
      *local_170 = local_98[0];
      pfVar8[2] = 0.0;
      pfVar8[3] = 0.0;
      pfVar8[4] = 0.0;
      pfVar8[5] = 0.0;
      pvVar13 = operator_new(0x20);
      *(void **)pvVar13 = pvVar13;
      *(void **)((longlong)pvVar13 + 8) = pvVar13;
      *(void **)(pfVar8 + 2) = pvVar13;
      pfVar8[6] = 0.0;
      pfVar8[7] = 0.0;
      pfVar8[8] = 0.0;
      pfVar8[9] = 0.0;
      pfVar8[10] = 0.0;
      pfVar8[0xb] = 0.0;
      FUN_140016fb0((ulonglong *)(pfVar8 + 6),0x10,*(undefined8 *)(pfVar8 + 2));
      uVar10 = uStack_60;
      uVar9 = local_68;
      uVar3 = *(undefined8 *)(pfVar8 + 2);
      *(void **)(pfVar8 + 2) = pvStack_90;
      uVar4 = *(undefined8 *)(pfVar8 + 4);
      *(undefined8 *)(pfVar8 + 4) = local_88;
      uVar27 = *(ulonglong *)(pfVar8 + 6);
      *(ulonglong *)(pfVar8 + 6) = uStack_80;
      uVar5 = *(undefined8 *)(pfVar8 + 8);
      *(undefined8 *)(pfVar8 + 8) = local_78;
      uVar6 = *(undefined8 *)(pfVar8 + 10);
      *(undefined8 *)(pfVar8 + 10) = uStack_70;
      local_68 = 7;
      *(undefined8 *)(pfVar8 + 0xc) = uVar9;
      uStack_60 = 8;
      *(undefined8 *)(pfVar8 + 0xe) = uVar10;
      pvStack_90 = (void *)uVar3;
      local_88 = uVar4;
      uStack_80 = uVar27;
      local_78 = uVar5;
      uStack_70 = uVar6;
      FUN_140010a90((longlong)local_98);
      goto LAB_14001ab29;
    }
    if (bVar2 == 0) {
      FUN_14000e950((longlong *)&local_b8,(undefined8 *)"cannot get value");
      FUN_140018ed0(local_130,0xd6,&local_b8);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_130,(ThrowInfo *)&DAT_140077d70);
    }
    if (bVar2 == 1) {
      pbVar21 = (byte *)(plVar16 + 8);
    }
    else {
      pbVar21 = pbVar25;
      if ((bVar2 != 2) && (pbVar21 = local_190, lVar24 != 0)) {
        FUN_14000e950((longlong *)&local_b8,(undefined8 *)"cannot get value");
        FUN_140018ed0(local_168,0xd6,&local_b8);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_168,(ThrowInfo *)&DAT_140077d70);
      }
    }
    local_48 = 0;
    local_40 = 0xf;
    local_58[0] = (undefined8 *****)0x0;
    local_194 = uVar32 | 2;
    local_180 = local_194;
    if (*pbVar21 != 3) {
      pcVar17 = FUN_14001ddd0(pbVar21);
      plVar16 = FUN_14000e950(local_168,(undefined8 *)pcVar17);
      puVar18 = FUN_140011fa0(&local_b8,(undefined8 *)"type must be string, but is ",plVar16,uVar27)
      ;
      FUN_1400190c0(local_130,0x12e,puVar18);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_130,(ThrowInfo *)&DAT_140077cc0);
    }
    pppppuVar23 = *(undefined8 ******)(pbVar21 + 8);
    if (local_58 != pppppuVar23) {
      pppppuVar1 = pppppuVar23 + 2;
      if ((undefined8 ****)0xf < pppppuVar23[3]) {
        pppppuVar23 = (undefined8 *****)*pppppuVar23;
      }
      FUN_1400106a0((longlong *)local_58,pppppuVar23,(ulonglong)*pppppuVar1);
    }
    pppppuVar23 = local_58;
    if (0xf < local_40) {
      pppppuVar23 = (undefined8 *****)local_58[0];
    }
    local_b8 = (longlong ****)0x0;
    uStack_a8 = 0;
    local_a0 = 0xf;
    uVar27 = 0xffffffffffffffff;
    do {
      uVar27 = uVar27 + 1;
    } while (*(char *)((longlong)pppppuVar23 + uVar27) != '\0');
    FUN_1400106a0((longlong *)&local_b8,pppppuVar23,uVar27);
    cVar34 = 0xf < local_a0;
    local_188 = local_b8;
    ppppplVar28 = &local_b8;
    if ((bool)cVar34) {
      ppppplVar28 = (longlong *****)local_b8;
    }
    uVar26 = 0xcbf29ce484222325;
    uVar27 = 0;
    if (uStack_a8 != 0) {
      do {
        uVar26 = (uVar26 ^ *(byte *)(uVar27 + (longlong)ppppplVar28)) * 0x100000001b3;
        uVar27 = uVar27 + 1;
      } while (uVar27 < uStack_a8);
    }
    puVar18 = *(undefined8 **)(DAT_14007d5d8 + 8 + (uVar26 & _DAT_14007d5f0) * 0x10);
    uVar27 = uStack_a8;
    local_198 = cVar34;
    if (puVar18 != DAT_14007d5c8) {
      local_178 = *(undefined8 **)(DAT_14007d5d8 + (uVar26 & _DAT_14007d5f0) * 0x10);
      ppppplVar28 = (longlong *****)local_b8;
      while( true ) {
        puVar14 = puVar18 + 2;
        if (0xf < (ulonglong)puVar18[5]) {
          puVar14 = (undefined8 *)*puVar14;
        }
        _Buf1 = &local_b8;
        if (cVar34 != '\0') {
          _Buf1 = ppppplVar28;
        }
        sVar30 = uVar27;
        if ((uVar27 == puVar18[4]) &&
           (iVar12 = memcmp(_Buf1,puVar14,uVar27), sVar30 = uStack_a8,
           ppppplVar28 = (longlong *****)local_188, cVar34 = local_198, iVar12 == 0)) break;
        uVar27 = sVar30;
        if (puVar18 == local_178) goto LAB_14001adff;
        puVar18 = (undefined8 *)puVar18[1];
      }
      if (puVar18 != (undefined8 *)0x0) goto LAB_14001ae06;
    }
LAB_14001adff:
    puVar18 = DAT_14007d5c8;
LAB_14001ae06:
    if (local_198 != '\0') {
      if ((0xfff < local_a0 + 1) &&
         (0x1f < (ulonglong)((longlong)local_188 + (-8 - (longlong)local_188[-1])))) {
        FUN_140035d28();
LAB_14001b114:
        FUN_140035d28();
LAB_14001b11a:
        plVar16 = FUN_14000e950((longlong *)&local_b8,(undefined8 *)"The registered event \'");
        plVar16 = FUN_140021a50(&local_f0,plVar16,local_58);
        plVar16 = FUN_1400219f0(local_168,plVar16,(undefined8 *)"\' is not recognized.");
        FUN_140001a40(local_d0,plVar16);
                    /* WARNING: Subroutine does not return */
        _CxxThrowException(local_d0,(ThrowInfo *)&DAT_140077818);
      }
      FUN_14002f180();
    }
    if (puVar18 == DAT_14007d5c8) goto LAB_14001b11a;
    if (*(int *)(puVar18 + 6) == 0) {
      puVar14 = (undefined8 *)operator_new(0x10);
      ppuVar15 = CBdServicePowerSourceEvent::vftable;
LAB_14001ae85:
      puVar14[1] = 0;
      *puVar14 = ppuVar15;
      if (puVar14 != (undefined8 *)0x0) {
        local_f0._0_4_ = *(undefined4 *)(puVar18 + 6);
        local_e8 = puVar14;
        FUN_1400261e0(local_98,local_d0,(byte *)&local_f0);
      }
    }
    else if (*(int *)(puVar18 + 6) == 1) {
      puVar14 = (undefined8 *)operator_new(0x10);
      ppuVar15 = CBdServiceBatteryPercentageEvent::vftable;
      goto LAB_14001ae85;
    }
    uVar32 = local_194 & 0xfffffffd;
    if (0xf < local_40) {
      if ((0xfff < local_40 + 1) &&
         (0x1f < (ulonglong)((longlong)local_58[0] + (-8 - (longlong)local_58[0][-1]))))
      goto LAB_14001b114;
      FUN_14002f180();
    }
    if (*local_190 == 1) {
      plVar7 = (longlong *)plVar16[2];
      if (*(char *)((longlong)plVar7 + 0x19) == '\0') {
        cVar34 = *(char *)(*plVar7 + 0x19);
        plVar16 = plVar7;
        plVar7 = (longlong *)*plVar7;
        while (cVar34 == '\0') {
          cVar34 = *(char *)(*plVar7 + 0x19);
          plVar16 = plVar7;
          plVar7 = (longlong *)*plVar7;
        }
      }
      else {
        cVar34 = *(char *)(plVar16[1] + 0x19);
        plVar11 = (longlong *)plVar16[1];
        plVar7 = plVar16;
        while ((plVar16 = plVar11, cVar34 == '\0' && (plVar7 == (longlong *)plVar16[2]))) {
          cVar34 = *(char *)(plVar16[1] + 0x19);
          plVar11 = (longlong *)plVar16[1];
          plVar7 = plVar16;
        }
      }
    }
    else if (*local_190 == 2) {
      pbVar25 = pbVar25 + 0x10;
    }
    else {
      lVar24 = lVar24 + 1;
    }
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_14001b1c0 @ 14001b1c0