void FUN_1400220b0(longlong param_1,longlong *param_2,ulonglong *param_3,longlong *param_4)

{
  longlong lVar1;
  undefined8 *puVar2;
  code *pcVar3;
  bool bVar4;
  char cVar5;
  short sVar6;
  int iVar7;
  undefined8 uVar8;
  ulonglong *puVar9;
  longlong *plVar10;
  longlong *plVar11;
  longlong lVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  longlong *plVar15;
  ulonglong *puVar16;
  ulonglong *puVar17;
  undefined1 auStackY_2f8 [32];
  ulonglong local_2c8;
  ulonglong uStack_2c0;
  ulonglong local_2b8;
  ulonglong uStack_2b0;
  undefined1 local_2a8;
  undefined7 uStack_2a7;
  undefined8 local_298;
  ulonglong local_290;
  ulonglong local_288;
  ulonglong uStack_280;
  ulonglong local_278;
  ulonglong uStack_270;
  longlong local_268;
  undefined8 uStack_260;
  undefined8 local_258;
  longlong local_250 [2];
  undefined8 local_240;
  ulonglong local_238;
  undefined8 **local_230;
  undefined8 local_228 [3];
  undefined **local_210;
  undefined8 local_208 [4];
  ulonglong local_1e8;
  ulonglong uStack_1e0;
  ulonglong local_1d8;
  ulonglong uStack_1d0;
  ulonglong local_1c8;
  ulonglong uStack_1c0;
  ulonglong local_1b8;
  ulonglong uStack_1b0;
  ulonglong local_1a8;
  ulonglong uStack_1a0;
  longlong local_198;
  ulonglong local_190;
  longlong local_188 [3];
  ulonglong local_170;
  longlong local_168 [2];
  longlong local_158 [2];
  longlong local_148 [2];
  longlong local_138 [2];
  undefined1 local_128 [16];
  undefined1 local_118 [16];
  undefined1 local_108 [16];
  undefined1 local_f8 [16];
  undefined1 local_e8 [16];
  undefined1 local_d8 [16];
  undefined1 local_c8 [16];
  longlong local_b8 [2];
  char local_a8 [8];
  char local_a0 [8];
  undefined8 local_98;
  longlong local_90;
  undefined8 uStack_88;
  undefined8 local_80;
  ulonglong uStack_78;
  undefined1 local_70 [8];
  undefined8 local_68;
  undefined1 local_60 [8];
  undefined8 local_58;
  ulonglong local_50;
  
  local_50 = DAT_14007a060 ^ (ulonglong)auStackY_2f8;
  local_90 = 0;
  uStack_88 = 0;
  local_80 = 0;
  uStack_78 = 0;
  bVar4 = false;
LAB_140022120:
  if (bVar4) {
    bVar4 = false;
    goto LAB_1400225df;
  }
  switch(*(undefined4 *)(param_1 + 0x40)) {
  case 1:
    local_a8[0] = '\x01';
    FUN_140027e40(param_2,local_f8,local_a8);
    break;
  case 2:
    local_a8[0] = '\0';
    FUN_140027e40(param_2,local_118,local_a8);
    break;
  case 3:
    FUN_140028190(param_2,local_108);
    break;
  case 4:
    FUN_1400270e0(param_2,local_d8,(undefined8 *)(param_1 + 0x90));
    break;
  case 5:
    local_98 = *(undefined8 *)(param_1 + 0xc0);
    FUN_1400277a0(param_2,local_c8,&local_98);
    break;
  case 6:
    local_98 = *(undefined8 *)(param_1 + 0xb8);
    FUN_140027af0(param_2,local_e8,&local_98);
    break;
  case 7:
    uVar8 = *(undefined8 *)(param_1 + 200);
    sVar6 = _dclass(uVar8);
    if (0 < sVar6) {
      puVar9 = (ulonglong *)FUN_14001f280(param_1 + 0x48,local_188,(ulonglong)param_3);
      uVar13 = puVar9[2];
      if (puVar9[3] - uVar13 < 0x19) {
        puVar9 = FUN_140014ae0(puVar9,0x19,uVar13,param_4,(undefined8 *)"number overflow parsing \'"
                               ,0x19);
      }
      else {
        puVar9[2] = uVar13 + 0x19;
        puVar16 = puVar9;
        if (0xf < puVar9[3]) {
          puVar16 = (ulonglong *)*puVar9;
        }
        if (((ulonglong *)0x14006d7b8 < puVar16) ||
           ((char *)((longlong)puVar16 + uVar13) < "number overflow parsing \'")) {
          puVar17 = (ulonglong *)0x19;
        }
        else if ("number overflow parsing \'" < puVar16) {
          puVar17 = puVar16 + -0x2800daf4;
        }
        else {
          puVar17 = (ulonglong *)0x0;
        }
        FUN_1400316b0((undefined8 *)((longlong)puVar16 + 0x19),puVar16,uVar13 + 1);
        FUN_1400316b0(puVar16,(undefined8 *)"number overflow parsing \'",(ulonglong)puVar17);
        FUN_1400316b0((undefined8 *)((longlong)puVar16 + (longlong)puVar17),
                      (undefined8 *)((longlong)puVar17 + 0x14006d7b9),0x19 - (longlong)puVar17);
      }
      local_2c8 = *puVar9;
      uStack_2c0 = puVar9[1];
      local_2b8 = puVar9[2];
      uStack_2b0 = puVar9[3];
      puVar9[2] = 0;
      puVar9[3] = 0xf;
      *(char *)puVar9 = '\0';
      puVar9 = (ulonglong *)FUN_140010800((longlong *)&local_2c8,(undefined8 *)&DAT_14006c918,1);
      local_288 = *puVar9;
      uStack_280 = puVar9[1];
      local_278 = puVar9[2];
      uStack_270 = puVar9[3];
      puVar9[2] = 0;
      puVar9[3] = 0xf;
      *(undefined1 *)puVar9 = 0;
      puVar9 = &local_288;
      lVar12 = FUN_1400192b0(&local_230,0x196,puVar9);
      plVar15 = (longlong *)&local_2a8;
      FUN_14001f280(param_1 + 0x48,plVar15,(ulonglong)puVar9);
      FUN_14001e410((longlong)param_2,plVar15,puVar9,lVar12);
      if (0xf < local_290) {
        if ((0xfff < local_290 + 1) &&
           (0x1f < (CONCAT71(uStack_2a7,local_2a8) -
                   *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) - 8U)) goto LAB_1400236e2;
        FUN_14002f180();
      }
      local_298 = 0;
      local_290 = 0xf;
      local_2a8 = 0;
      local_210 = std::exception::vftable;
      __std_exception_destroy(local_208);
      local_230 = (undefined8 **)std::exception::vftable;
      __std_exception_destroy(local_228);
      if (0xf < uStack_270) {
        if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8))
        goto LAB_1400236e8;
        FUN_14002f180();
      }
      if (0xf < uStack_2b0) {
        if ((0xfff < uStack_2b0 + 1) && (0x1f < (local_2c8 - *(longlong *)(local_2c8 - 8)) - 8))
        goto LAB_1400236ee;
        FUN_14002f180();
      }
      local_2b8 = 0;
      uStack_2b0 = 0xf;
      local_2c8 = local_2c8 & 0xffffffffffffff00;
      if (local_170 < 0x10) goto LAB_14002364c;
      if ((0xfff < local_170 + 1) && (0x1f < (local_188[0] - *(longlong *)(local_188[0] + -8)) - 8U)
         ) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      goto LAB_14002341a;
    }
    local_98 = uVar8;
    FUN_140027450(param_2,local_128,&local_98);
    break;
  case 8:
    local_a8[0] = '\x02';
    local_98 = CONCAT44(local_98._4_4_,(int)(param_2[2] - param_2[1] >> 3));
    if (param_2[0x15] == 0) {
      FUN_14002d6d4();
LAB_1400236e2:
      FUN_140035d28();
LAB_1400236e8:
      FUN_140035d28();
LAB_1400236ee:
      FUN_140035d28();
LAB_1400236f4:
      FUN_140035d28();
LAB_1400236fa:
      FUN_140035d28();
LAB_140023700:
      FUN_140035d28();
LAB_140023706:
      FUN_140035d28();
      goto LAB_14002370c;
    }
    param_4 = param_2 + 0x17;
    local_a0[0] = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_2[0x15],&local_98,local_a8);
    uVar13 = param_2[7];
    if (((longlong)uVar13 < 0) && (uVar13 != 0)) {
      lVar12 = -((~uVar13 >> 5) * 4 + 4);
    }
    else {
      lVar12 = (uVar13 >> 5) * 4;
    }
    local_1c8 = param_2[4] + lVar12;
    uStack_2c0 = (ulonglong)((uint)uVar13 & 0x1f);
    local_2c8 = local_1c8;
    uStack_1c0 = uStack_2c0;
    FUN_1400214b0(param_2 + 4,local_148,&local_2c8,param_4,local_a0);
    local_a0[0] = '\x02';
    FUN_140026af0(param_2,local_60,local_a0);
    puVar2 = (undefined8 *)param_2[2];
    if (puVar2 == (undefined8 *)param_2[3]) {
      FUN_1400284e0(param_2 + 1,puVar2,&local_58);
    }
    else {
      *puVar2 = local_58;
      param_2[2] = param_2[2] + 8;
    }
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 10) {
      uVar8 = FUN_140024ff0((longlong)param_2);
      cVar5 = (char)uVar8;
joined_r0x000140022266:
      if (cVar5 != '\0') break;
      goto LAB_14002364c;
    }
    local_a8[0] = '\x01';
    if (((longlong)uStack_78 < 0) && (uStack_78 != 0)) {
      lVar12 = -((~uStack_78 >> 5) * 4 + 4);
    }
    else {
      lVar12 = (uStack_78 >> 5) * 4;
    }
    local_2c8 = local_90 + lVar12;
    uStack_2c0 = (ulonglong)((uint)uStack_78 & 0x1f);
    param_3 = &local_2c8;
    local_1b8 = local_2c8;
    uStack_1b0 = uStack_2c0;
    FUN_1400214b0(&local_90,local_138,param_3,param_4,local_a8);
    goto LAB_140022120;
  case 9:
    local_a0[0] = '\0';
    local_98 = CONCAT44(local_98._4_4_,(int)(param_2[2] - param_2[1] >> 3));
    if (param_2[0x15] == 0) goto LAB_1400236d6;
    param_4 = param_2 + 0x17;
    local_a8[0] = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_2[0x15],&local_98,local_a0);
    uVar13 = param_2[7];
    if (((longlong)uVar13 < 0) && (uVar13 != 0)) {
      lVar12 = -((~uVar13 >> 5) * 4 + 4);
    }
    else {
      lVar12 = (uVar13 >> 5) * 4;
    }
    local_1e8 = param_2[4] + lVar12;
    uStack_2c0 = (ulonglong)((uint)uVar13 & 0x1f);
    local_2c8 = local_1e8;
    uStack_1e0 = uStack_2c0;
    FUN_1400214b0(param_2 + 4,local_168,&local_2c8,param_4,local_a8);
    local_a8[0] = '\x01';
    FUN_140026af0(param_2,local_70,local_a8);
    puVar2 = (undefined8 *)param_2[2];
    if (puVar2 == (undefined8 *)param_2[3]) {
      FUN_1400284e0(param_2 + 1,puVar2,&local_68);
    }
    else {
      *puVar2 = local_68;
      param_2[2] = param_2[2] + 8;
    }
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 0xb) {
      cVar5 = FUN_1400250e0((longlong)param_2);
      goto joined_r0x000140022266;
    }
    if (*(int *)(param_1 + 0x40) == 4) {
      cVar5 = FUN_140025440((longlong)param_2,(undefined8 *)(param_1 + 0x90));
      if (cVar5 == '\0') goto LAB_14002364c;
      iVar7 = FUN_14001ef90(param_1);
      if (iVar7 == 0xc) goto code_r0x0001400222a2;
      local_2b8 = 0;
      uStack_2b0 = 0xf;
      local_2c8 = 0;
      FUN_1400106a0((longlong *)&local_2c8,(undefined8 *)"object separator",0x10);
      plVar11 = (longlong *)&local_2a8;
      plVar10 = FUN_14001e680(param_1,plVar11,0xc,&local_2c8);
      local_268 = *(longlong *)(param_1 + 0x60);
      uStack_260 = *(undefined8 *)(param_1 + 0x68);
      local_258 = *(undefined8 *)(param_1 + 0x70);
      plVar15 = &local_268;
      lVar12 = FUN_1400186d0(&local_230,plVar11,plVar15,plVar10);
      puVar9 = &local_288;
      FUN_14001f280(param_1 + 0x48,(longlong *)puVar9,(ulonglong)plVar15);
      FUN_14001e410((longlong)param_2,puVar9,plVar15,lVar12);
      if (0xf < uStack_270) {
        if ((uStack_270 + 1 < 0x1000) || ((local_288 - *(longlong *)(local_288 - 8)) - 8 < 0x20)) {
          FUN_14002f180();
          goto LAB_1400228fe;
        }
        goto LAB_1400236be;
      }
LAB_1400228fe:
      local_278 = 0;
      uStack_270 = 0xf;
      local_288 = local_288 & 0xffffffffffffff00;
      local_210 = std::exception::vftable;
      __std_exception_destroy(local_208);
      local_230 = (undefined8 **)std::exception::vftable;
      __std_exception_destroy(local_228);
      if (0xf < local_290) {
        if ((local_290 + 1 < 0x1000) ||
           ((CONCAT71(uStack_2a7,local_2a8) - *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) -
            8U < 0x20)) {
          FUN_14002f180();
          goto LAB_14002296e;
        }
        goto LAB_1400236c4;
      }
LAB_14002296e:
      local_298 = 0;
      local_290 = 0xf;
      local_2a8 = 0;
      if (uStack_2b0 < 0x10) goto LAB_14002364c;
      if ((0xfff < uStack_2b0 + 1) && (0x1f < (local_2c8 - *(longlong *)(local_2c8 - 8)) - 8))
      goto LAB_140023694;
    }
    else {
      local_2b8 = 0;
      uStack_2b0 = 0xf;
      local_2c8 = 0;
      FUN_1400106a0((longlong *)&local_2c8,(undefined8 *)"object key",10);
      puVar9 = &local_288;
      plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,4,&local_2c8);
      local_268 = *(longlong *)(param_1 + 0x60);
      uStack_260 = *(undefined8 *)(param_1 + 0x68);
      local_258 = *(undefined8 *)(param_1 + 0x70);
      plVar15 = &local_268;
      lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
      plVar11 = (longlong *)&local_2a8;
      FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
      FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
      if (0xf < local_290) {
        if ((local_290 + 1 < 0x1000) ||
           ((CONCAT71(uStack_2a7,local_2a8) - *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) -
            8U < 0x20)) {
          FUN_14002f180();
          goto LAB_140022a8e;
        }
        goto LAB_1400236ca;
      }
LAB_140022a8e:
      local_298 = 0;
      local_290 = 0xf;
      local_2a8 = 0;
      local_210 = std::exception::vftable;
      __std_exception_destroy(local_208);
      local_230 = (undefined8 **)std::exception::vftable;
      __std_exception_destroy(local_228);
      if (0xf < uStack_270) {
        if ((uStack_270 + 1 < 0x1000) || ((local_288 - *(longlong *)(local_288 - 8)) - 8 < 0x20)) {
          FUN_14002f180();
          goto LAB_140022aff;
        }
        goto LAB_1400236d0;
      }
LAB_140022aff:
      local_278 = 0;
      uStack_270 = 0xf;
      local_288 = local_288 & 0xffffffffffffff00;
      if (uStack_2b0 < 0x10) goto LAB_14002364c;
      if ((0xfff < uStack_2b0 + 1) && (0x1f < (local_2c8 - *(longlong *)(local_2c8 - 8)) - 8)) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
    }
    goto LAB_14002341a;
  default:
    local_240 = 0;
    local_238 = 0xf;
    local_250[0] = 0;
    FUN_1400106a0(local_250,(undefined8 *)"value",5);
    puVar9 = &local_288;
    plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,0x10,local_250);
    local_268 = *(longlong *)(param_1 + 0x60);
    uStack_260 = *(undefined8 *)(param_1 + 0x68);
    local_258 = *(undefined8 *)(param_1 + 0x70);
    plVar15 = &local_268;
    lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
    plVar11 = (longlong *)&local_2a8;
    FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
    FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
    if (0xf < local_290) {
      if ((0xfff < local_290 + 1) &&
         (0x1f < (CONCAT71(uStack_2a7,local_2a8) -
                 *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) - 8U)) goto LAB_140023700;
      FUN_14002f180();
    }
    local_298 = 0;
    local_290 = 0xf;
    local_2a8 = 0;
    local_210 = std::exception::vftable;
    __std_exception_destroy(local_208);
    local_230 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_228);
    if (0xf < uStack_270) {
      if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8))
      goto LAB_140023706;
      FUN_14002f180();
    }
    local_278 = 0;
    uStack_270 = 0xf;
    local_288 = local_288 & 0xffffffffffffff00;
    if (local_238 < 0x10) goto LAB_14002364c;
    if ((0xfff < local_238 + 1) && (0x1f < (local_250[0] - *(longlong *)(local_250[0] + -8)) - 8U))
    {
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    goto LAB_14002341a;
  case 0xe:
    local_240 = 0;
    local_238 = 0xf;
    local_250[0] = 0;
    FUN_1400106a0(local_250,(undefined8 *)"value",5);
    puVar9 = &local_288;
    plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,0,local_250);
    local_268 = *(longlong *)(param_1 + 0x60);
    uStack_260 = *(undefined8 *)(param_1 + 0x68);
    local_258 = *(undefined8 *)(param_1 + 0x70);
    plVar15 = &local_268;
    lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
    plVar11 = (longlong *)&local_2a8;
    FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
    FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
    if (0xf < local_290) {
      if ((0xfff < local_290 + 1) &&
         (0x1f < (CONCAT71(uStack_2a7,local_2a8) -
                 *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) - 8U)) goto LAB_1400236f4;
      FUN_14002f180();
    }
    local_298 = 0;
    local_290 = 0xf;
    local_2a8 = 0;
    local_210 = std::exception::vftable;
    __std_exception_destroy(local_208);
    local_230 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_228);
    if (0xf < uStack_270) {
      if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8))
      goto LAB_1400236fa;
      FUN_14002f180();
    }
    local_278 = 0;
    uStack_270 = 0xf;
    local_288 = local_288 & 0xffffffffffffff00;
    if (local_238 < 0x10) goto LAB_14002364c;
    if ((0xfff < local_238 + 1) && (0x1f < (local_250[0] - *(longlong *)(local_250[0] + -8)) - 8U))
    {
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    goto LAB_14002341a;
  }
LAB_1400225df:
  if (uStack_78 == 0) goto LAB_14002364c;
  if (((longlong)uStack_78 < 0) && (uStack_78 != 0)) {
    lVar12 = -((~uStack_78 >> 5) * 4 + 4);
  }
  else {
    lVar12 = (uStack_78 >> 5) * 4;
  }
  uVar13 = (ulonglong)((uint)uStack_78 & 0x1f);
  uVar14 = uVar13 - 1;
  if (uVar13 == 0) {
    lVar1 = -((~uVar14 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar14 >> 5) * 4;
  }
  param_3 = (ulonglong *)(local_90 + lVar12 + lVar1);
  if (((uint)*param_3 & 1 << ((byte)uVar14 & 0x1f)) != 0) {
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 0xd) {
      FUN_14001ef90(param_1);
    }
    else {
      if (*(int *)(param_1 + 0x40) != 10) {
        local_240 = 0;
        local_238 = 0xf;
        local_250[0] = 0;
        FUN_1400106a0(local_250,(undefined8 *)"array",5);
        puVar9 = &local_288;
        plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,10,local_250);
        local_268 = *(longlong *)(param_1 + 0x60);
        uStack_260 = *(undefined8 *)(param_1 + 0x68);
        local_258 = *(undefined8 *)(param_1 + 0x70);
        plVar15 = &local_268;
        lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
        plVar11 = (longlong *)&local_2a8;
        FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
        FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
        if (local_290 < 0x10) {
LAB_1400231cf:
          local_298 = 0;
          local_290 = 0xf;
          local_2a8 = 0;
          local_210 = std::exception::vftable;
          __std_exception_destroy(local_208);
          local_230 = (undefined8 **)std::exception::vftable;
          __std_exception_destroy(local_228);
          if (0xf < uStack_270) {
            if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8))
            goto LAB_140023712;
            FUN_14002f180();
          }
          local_278 = 0;
          uStack_270 = 0xf;
          local_288 = local_288 & 0xffffffffffffff00;
          if (local_238 < 0x10) goto LAB_14002364c;
          if ((0xfff < local_238 + 1) &&
             (0x1f < (local_250[0] - *(longlong *)(local_250[0] + -8)) - 8U)) {
            FUN_140035d28();
            pcVar3 = (code *)swi(3);
            (*pcVar3)();
            return;
          }
          goto LAB_14002341a;
        }
        if ((local_290 + 1 < 0x1000) ||
           ((CONCAT71(uStack_2a7,local_2a8) - *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) -
            8U < 0x20)) {
          FUN_14002f180();
          goto LAB_1400231cf;
        }
LAB_14002370c:
        FUN_140035d28();
LAB_140023712:
        FUN_140035d28();
        goto LAB_140023718;
      }
      uVar8 = FUN_140024ff0((longlong)param_2);
      if ((char)uVar8 == '\0') goto LAB_14002364c;
      if (((longlong)uStack_78 < 0) && (uStack_78 != 0)) {
        lVar12 = -((~uStack_78 >> 5) * 4 + 4);
      }
      else {
        lVar12 = (uStack_78 >> 5) * 4;
      }
      uVar14 = (ulonglong)((uint)uStack_78 & 0x1f);
      uVar13 = uVar14 - 1;
      if (uVar14 == 0) {
        lVar1 = -((~uVar13 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar13 >> 5) * 4;
      }
      local_1a8 = local_90 + lVar12 + lVar1;
      uStack_2c0 = (ulonglong)((uint)uVar13 & 0x1f);
      local_2c8 = local_1a8;
      param_3 = &local_2c8;
      uStack_1a0 = uStack_2c0;
      FUN_140025f10(&local_90,local_b8,(longlong *)param_3);
      bVar4 = true;
    }
    goto LAB_140022120;
  }
  iVar7 = FUN_14001ef90(param_1);
  if (iVar7 != 0xd) {
    if (*(int *)(param_1 + 0x40) != 0xb) {
      FUN_14000e950(local_188,(undefined8 *)"object");
      puVar9 = &local_288;
      plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,0xb,local_188);
      local_268 = *(longlong *)(param_1 + 0x60);
      uStack_260 = *(undefined8 *)(param_1 + 0x68);
      local_258 = *(undefined8 *)(param_1 + 0x70);
      plVar15 = &local_268;
      lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
      plVar11 = (longlong *)&local_2a8;
      FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
      FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
      FUN_14000e8f0((longlong *)&local_2a8);
      FUN_140018e30(&local_230);
      FUN_14000e8f0((longlong *)&local_288);
      FUN_14000e8f0(local_188);
      goto LAB_14002364c;
    }
    cVar5 = FUN_1400250e0((longlong)param_2);
    if (cVar5 == '\0') goto LAB_14002364c;
    if (((longlong)uStack_78 < 0) && (uStack_78 != 0)) {
      local_198 = -((~uStack_78 >> 5) * 4 + 4);
    }
    else {
      local_198 = (uStack_78 >> 5) * 4;
    }
    local_198 = local_90 + local_198;
    local_190 = (ulonglong)((uint)uStack_78 & 0x1f);
    puVar9 = (ulonglong *)FUN_140025b30(&local_198,local_250);
    local_2c8 = *puVar9;
    uStack_2c0 = puVar9[1];
    param_3 = &local_2c8;
    FUN_140025f10(&local_90,&local_268,(longlong *)param_3);
    bVar4 = true;
    goto LAB_140022120;
  }
  iVar7 = FUN_14001ef90(param_1);
  if (iVar7 != 4) {
    local_2b8 = 0;
    uStack_2b0 = 0xf;
    local_2c8 = 0;
    FUN_1400106a0((longlong *)&local_2c8,(undefined8 *)"object key",10);
    puVar9 = &local_288;
    plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,4,&local_2c8);
    local_268 = *(longlong *)(param_1 + 0x60);
    uStack_260 = *(undefined8 *)(param_1 + 0x68);
    local_258 = *(undefined8 *)(param_1 + 0x70);
    plVar15 = &local_268;
    lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
    plVar11 = (longlong *)&local_2a8;
    FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
    FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
    if (0xf < local_290) {
      if ((0xfff < local_290 + 1) &&
         (0x1f < (CONCAT71(uStack_2a7,local_2a8) -
                 *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) - 8U)) goto LAB_14002372a;
      FUN_14002f180();
    }
    local_298 = 0;
    local_290 = 0xf;
    local_2a8 = 0;
    local_210 = std::exception::vftable;
    __std_exception_destroy(local_208);
    local_230 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_228);
    if (0xf < uStack_270) {
      if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8)) {
        FUN_140035d28();
LAB_140023694:
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_14002f180();
    }
    local_278 = 0;
    uStack_270 = 0xf;
    local_288 = local_288 & 0xffffffffffffff00;
    if (uStack_2b0 < 0x10) goto LAB_14002364c;
    if ((0xfff < uStack_2b0 + 1) && (0x1f < (local_2c8 - *(longlong *)(local_2c8 - 8)) - 8)) {
      FUN_140035d28();
LAB_1400236be:
      FUN_140035d28();
LAB_1400236c4:
      FUN_140035d28();
LAB_1400236ca:
      FUN_140035d28();
LAB_1400236d0:
      FUN_140035d28();
LAB_1400236d6:
      FUN_14002d6d4();
      pcVar3 = (code *)swi(3);
      (*pcVar3)();
      return;
    }
    goto LAB_14002341a;
  }
  cVar5 = FUN_140025440((longlong)param_2,(undefined8 *)(param_1 + 0x90));
  if (cVar5 == '\0') goto LAB_14002364c;
  iVar7 = FUN_14001ef90(param_1);
  if (iVar7 == 0xc) {
    FUN_14001ef90(param_1);
    goto LAB_140022120;
  }
  local_2b8 = 0;
  uStack_2b0 = 0xf;
  local_2c8 = 0;
  FUN_1400106a0((longlong *)&local_2c8,(undefined8 *)"object separator",0x10);
  puVar9 = &local_288;
  plVar11 = FUN_14001e680(param_1,(longlong *)puVar9,0xc,&local_2c8);
  local_268 = *(longlong *)(param_1 + 0x60);
  uStack_260 = *(undefined8 *)(param_1 + 0x68);
  local_258 = *(undefined8 *)(param_1 + 0x70);
  plVar15 = &local_268;
  lVar12 = FUN_1400186d0(&local_230,puVar9,plVar15,plVar11);
  plVar11 = (longlong *)&local_2a8;
  FUN_14001f280(param_1 + 0x48,plVar11,(ulonglong)plVar15);
  FUN_14001e410((longlong)param_2,plVar11,plVar15,lVar12);
  if (local_290 < 0x10) {
LAB_14002335c:
    local_298 = 0;
    local_290 = 0xf;
    local_2a8 = 0;
    local_210 = std::exception::vftable;
    __std_exception_destroy(local_208);
    local_230 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_228);
    if (0xf < uStack_270) {
      if ((0xfff < uStack_270 + 1) && (0x1f < (local_288 - *(longlong *)(local_288 - 8)) - 8))
      goto LAB_14002371e;
      FUN_14002f180();
    }
    local_278 = 0;
    uStack_270 = 0xf;
    local_288 = local_288 & 0xffffffffffffff00;
    if (0xf < uStack_2b0) {
      if ((0xfff < uStack_2b0 + 1) && (0x1f < (local_2c8 - *(longlong *)(local_2c8 - 8)) - 8))
      goto LAB_140023724;
LAB_14002341a:
      FUN_14002f180();
    }
LAB_14002364c:
    FUN_14001f390(&local_90);
    FUN_14002f160(local_50 ^ (ulonglong)auStackY_2f8);
    return;
  }
  if ((local_290 + 1 < 0x1000) ||
     ((CONCAT71(uStack_2a7,local_2a8) - *(longlong *)(CONCAT71(uStack_2a7,local_2a8) + -8)) - 8U <
      0x20)) {
    FUN_14002f180();
    goto LAB_14002335c;
  }
LAB_140023718:
  FUN_140035d28();
LAB_14002371e:
  FUN_140035d28();
LAB_140023724:
  FUN_140035d28();
LAB_14002372a:
  FUN_140035d28();
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
code_r0x0001400222a2:
  local_a8[0] = '\0';
  if (((longlong)uStack_78 < 0) && (uStack_78 != 0)) {
    lVar12 = -((~uStack_78 >> 5) * 4 + 4);
  }
  else {
    lVar12 = (uStack_78 >> 5) * 4;
  }
  local_2c8 = local_90 + lVar12;
  uStack_2c0 = (ulonglong)((uint)uStack_78 & 0x1f);
  param_3 = &local_2c8;
  local_1d8 = local_2c8;
  uStack_1d0 = uStack_2c0;
  FUN_1400214b0(&local_90,local_158,param_3,param_4,local_a8);
  FUN_14001ef90(param_1);
  goto LAB_140022120;
}


// FUNCTION_END

// FUNCTION_START: FUN_140023770 @ 140023770