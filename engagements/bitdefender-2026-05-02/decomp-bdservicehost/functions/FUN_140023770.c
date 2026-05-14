void FUN_140023770(longlong param_1,undefined8 *param_2,char ****param_3,undefined8 param_4)

{
  char cVar1;
  char *******pppppppcVar2;
  undefined8 *puVar3;
  code *pcVar4;
  bool bVar5;
  short sVar6;
  int iVar7;
  char *pcVar8;
  longlong *plVar9;
  undefined8 uVar10;
  longlong *plVar11;
  ulonglong *puVar12;
  longlong *plVar13;
  longlong lVar14;
  undefined1 *puVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  char *pcVar18;
  char ********ppppppppcVar19;
  char *pcVar20;
  undefined1 auStackY_328 [32];
  undefined1 local_2f8;
  undefined7 uStack_2f7;
  undefined8 local_2e8;
  ulonglong local_2e0;
  ulonglong local_2d8;
  ulonglong uStack_2d0;
  ulonglong local_2c8;
  ulonglong uStack_2c0;
  longlong local_2b8;
  undefined8 uStack_2b0;
  undefined8 local_2a8;
  longlong local_2a0 [2];
  undefined8 local_290;
  ulonglong local_288;
  undefined8 **local_280;
  undefined8 local_278 [3];
  undefined **local_260;
  undefined8 local_258 [3];
  longlong local_240 [3];
  ulonglong local_228;
  char local_220 [8];
  undefined8 local_218;
  char local_210 [8];
  undefined8 local_208;
  char local_200 [8];
  undefined8 local_1f8;
  char local_1f0 [8];
  undefined8 local_1e8;
  char local_1e0 [8];
  undefined8 local_1d8;
  char local_1d0 [8];
  undefined8 local_1c8;
  char *******local_1b8;
  ulonglong uStack_1b0;
  char *******local_1a8;
  ulonglong uStack_1a0;
  char local_198 [8];
  undefined8 local_190;
  char local_188 [8];
  undefined8 local_180;
  char local_178 [8];
  undefined8 local_170;
  char local_168 [8];
  undefined8 local_160;
  char local_158 [8];
  undefined8 local_150;
  char local_148 [8];
  undefined8 local_140;
  undefined1 local_138;
  uint7 uStack_137;
  undefined1 local_130;
  undefined7 uStack_12f;
  undefined1 local_128;
  undefined7 uStack_127;
  undefined1 local_120;
  undefined7 uStack_11f;
  undefined1 local_118;
  uint7 uStack_117;
  undefined1 local_110;
  uint7 uStack_10f;
  longlong local_108;
  ulonglong local_100;
  char local_f8 [16];
  char local_e8 [16];
  char local_d8 [16];
  char local_c8 [16];
  undefined8 local_b8 [2];
  undefined1 local_a8 [16];
  char *******local_98;
  ulonglong uStack_90;
  undefined8 local_88;
  ulonglong uStack_80;
  longlong local_78 [8];
  
  local_78[4] = DAT_14007a060 ^ (ulonglong)auStackY_328;
  local_78[0] = 0;
  local_78[1] = 0;
  local_78[2] = 0;
  local_78[3] = 0;
  bVar5 = false;
LAB_1400237e0:
  if (bVar5) {
    bVar5 = false;
    goto LAB_140024017;
  }
  switch(*(undefined4 *)(param_1 + 0x40)) {
  case 1:
    local_a8[0] = '\x01';
    if (param_2[1] == param_2[2]) {
      local_120 = 1;
      pcVar8 = (char *)*param_2;
      local_178[0] = *pcVar8;
      *pcVar8 = '\x04';
      local_170 = *(undefined8 *)(pcVar8 + 8);
      *(ulonglong *)(pcVar8 + 8) = CONCAT71(uStack_11f,1);
      FUN_14001cf70(local_178);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        puVar15 = (undefined1 *)plVar9[1];
        if (puVar15 == (undefined1 *)plVar9[2]) {
LAB_140023e70:
          param_3 = (char ****)local_a8;
          FUN_140029850(plVar9,puVar15,(undefined1 *)param_3);
        }
        else {
          *puVar15 = 4;
          local_128 = 1;
          *(ulonglong *)(puVar15 + 8) = CONCAT71(uStack_127,1);
          plVar9[1] = plVar9[1] + 0x10;
        }
      }
      else {
        local_130 = 1;
        pcVar8 = (char *)param_2[4];
        local_168[0] = *pcVar8;
        *pcVar8 = '\x04';
        local_160 = *(undefined8 *)(pcVar8 + 8);
        *(ulonglong *)(pcVar8 + 8) = CONCAT71(uStack_12f,1);
        FUN_14001cf70(local_168);
      }
    }
    break;
  case 2:
    local_a8[0] = '\0';
    if (param_2[1] == param_2[2]) {
      local_138 = 0;
      pcVar8 = (char *)*param_2;
      local_198[0] = *pcVar8;
      *pcVar8 = '\x04';
      local_190 = *(undefined8 *)(pcVar8 + 8);
      *(ulonglong *)(pcVar8 + 8) = (ulonglong)uStack_137 << 8;
      FUN_14001cf70(local_198);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        puVar15 = (undefined1 *)plVar9[1];
        if (puVar15 == (undefined1 *)plVar9[2]) goto LAB_140023e70;
        *puVar15 = 4;
        local_110 = 0;
        *(ulonglong *)(puVar15 + 8) = (ulonglong)uStack_10f << 8;
        plVar9[1] = plVar9[1] + 0x10;
      }
      else {
        local_118 = 0;
        pcVar8 = (char *)param_2[4];
        local_188[0] = *pcVar8;
        *pcVar8 = '\x04';
        local_180 = *(undefined8 *)(pcVar8 + 8);
        *(ulonglong *)(pcVar8 + 8) = (ulonglong)uStack_117 << 8;
        FUN_14001cf70(local_188);
      }
    }
    break;
  case 3:
    if (param_2[1] == param_2[2]) {
      FUN_14001de50(local_220,'\0');
      pcVar8 = (char *)*param_2;
      cVar1 = *pcVar8;
      *pcVar8 = local_220[0];
      uVar10 = *(undefined8 *)(pcVar8 + 8);
      *(undefined8 *)(pcVar8 + 8) = local_218;
      local_220[0] = cVar1;
      local_218 = uVar10;
      FUN_14001cf70(local_220);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        pcVar8 = (char *)plVar9[1];
        if (pcVar8 == (char *)plVar9[2]) {
          FUN_140029a20(plVar9,pcVar8);
        }
        else {
          FUN_14001de50(pcVar8,'\0');
          plVar9[1] = plVar9[1] + 0x10;
        }
      }
      else {
        FUN_14001de50(local_210,'\0');
        pcVar8 = (char *)param_2[4];
        cVar1 = *pcVar8;
        *pcVar8 = local_210[0];
        uVar10 = *(undefined8 *)(pcVar8 + 8);
        *(undefined8 *)(pcVar8 + 8) = local_208;
        local_210[0] = cVar1;
        local_208 = uVar10;
        FUN_14001cf70(local_210);
      }
    }
    break;
  case 4:
    FUN_140026960(param_2,(undefined8 *)(param_1 + 0x90));
    break;
  case 5:
    param_3 = *(char *****)(param_1 + 0xc0);
    local_98 = (char *******)param_3;
    if (param_2[1] == param_2[2]) {
      pcVar8 = (char *)*param_2;
      local_1e0[0] = *pcVar8;
      *pcVar8 = '\x06';
      local_1d8 = *(undefined8 *)(pcVar8 + 8);
      *(char *****)(pcVar8 + 8) = param_3;
      FUN_14001cf70(local_1e0);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        puVar15 = (undefined1 *)plVar9[1];
        if (puVar15 == (undefined1 *)plVar9[2]) {
          ppppppppcVar19 = &local_98;
          FUN_1400294b0(plVar9,puVar15,ppppppppcVar19);
          param_3 = (char ****)ppppppppcVar19;
        }
        else {
          *puVar15 = 6;
          *(char *****)(puVar15 + 8) = param_3;
          plVar9[1] = plVar9[1] + 0x10;
        }
      }
      else {
        pcVar8 = (char *)param_2[4];
        local_1d0[0] = *pcVar8;
        *pcVar8 = '\x06';
        local_1c8 = *(undefined8 *)(pcVar8 + 8);
        *(char *****)(pcVar8 + 8) = param_3;
        FUN_14001cf70(local_1d0);
      }
    }
    break;
  case 6:
    param_3 = *(char *****)(param_1 + 0xb8);
    local_98 = (char *******)param_3;
    if (param_2[1] == param_2[2]) {
      pcVar8 = (char *)*param_2;
      local_158[0] = *pcVar8;
      *pcVar8 = '\x05';
      local_150 = *(undefined8 *)(pcVar8 + 8);
      *(char *****)(pcVar8 + 8) = param_3;
      FUN_14001cf70(local_158);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        puVar15 = (undefined1 *)plVar9[1];
        if (puVar15 == (undefined1 *)plVar9[2]) {
          ppppppppcVar19 = &local_98;
          FUN_140029680(plVar9,puVar15,ppppppppcVar19);
          param_3 = (char ****)ppppppppcVar19;
        }
        else {
          *puVar15 = 5;
          *(char *****)(puVar15 + 8) = param_3;
          plVar9[1] = plVar9[1] + 0x10;
        }
      }
      else {
        pcVar8 = (char *)param_2[4];
        local_148[0] = *pcVar8;
        *pcVar8 = '\x05';
        local_140 = *(undefined8 *)(pcVar8 + 8);
        *(char *****)(pcVar8 + 8) = param_3;
        FUN_14001cf70(local_148);
      }
    }
    break;
  case 7:
    ppppppppcVar19 = *(char *********)(param_1 + 200);
    sVar6 = _dclass(ppppppppcVar19);
    if (0 < sVar6) {
      pcVar8 = (char *)FUN_14001f280(param_1 + 0x48,local_240,(ulonglong)param_3);
      lVar14 = *(longlong *)(pcVar8 + 0x10);
      if (*(ulonglong *)(pcVar8 + 0x18) - lVar14 < 0x19) {
        pcVar8 = (char *)FUN_140014ae0((undefined8 *)pcVar8,0x19,lVar14,param_4,
                                       (undefined8 *)"number overflow parsing \'",0x19);
      }
      else {
        *(longlong *)(pcVar8 + 0x10) = lVar14 + 0x19;
        pcVar18 = pcVar8;
        if (0xf < *(ulonglong *)(pcVar8 + 0x18)) {
          pcVar18 = *(char **)pcVar8;
        }
        if (("\'" < pcVar18) || (pcVar18 + lVar14 < "number overflow parsing \'")) {
          pcVar20 = (char *)0x19;
        }
        else if ("number overflow parsing \'" < pcVar18) {
          pcVar20 = pcVar18 + -0x14006d7a0;
        }
        else {
          pcVar20 = (char *)0x0;
        }
        FUN_1400316b0((undefined8 *)(pcVar18 + 0x19),(undefined8 *)pcVar18,lVar14 + 1);
        FUN_1400316b0((undefined8 *)pcVar18,(undefined8 *)"number overflow parsing \'",
                      (ulonglong)pcVar20);
        FUN_1400316b0((undefined8 *)(pcVar18 + (longlong)pcVar20),
                      (undefined8 *)(pcVar20 + 0x14006d7b9),0x19 - (longlong)pcVar20);
      }
      local_98 = *(char ********)pcVar8;
      uStack_90 = *(ulonglong *)(pcVar8 + 8);
      local_88 = *(undefined8 *)(pcVar8 + 0x10);
      uStack_80 = *(ulonglong *)(pcVar8 + 0x18);
      pcVar8[0x10] = '\0';
      pcVar8[0x11] = '\0';
      pcVar8[0x12] = '\0';
      pcVar8[0x13] = '\0';
      pcVar8[0x14] = '\0';
      pcVar8[0x15] = '\0';
      pcVar8[0x16] = '\0';
      pcVar8[0x17] = '\0';
      pcVar8[0x18] = '\x0f';
      pcVar8[0x19] = '\0';
      pcVar8[0x1a] = '\0';
      pcVar8[0x1b] = '\0';
      pcVar8[0x1c] = '\0';
      pcVar8[0x1d] = '\0';
      pcVar8[0x1e] = '\0';
      pcVar8[0x1f] = '\0';
      *pcVar8 = '\0';
      puVar12 = (ulonglong *)FUN_140010800((longlong *)&local_98,(undefined8 *)&DAT_14006c918,1);
      local_2d8 = *puVar12;
      uStack_2d0 = puVar12[1];
      local_2c8 = puVar12[2];
      uStack_2c0 = puVar12[3];
      puVar12[2] = 0;
      puVar12[3] = 0xf;
      *(undefined1 *)puVar12 = 0;
      puVar12 = &local_2d8;
      lVar14 = FUN_1400192b0(&local_280,0x196,puVar12);
      plVar9 = (longlong *)&local_2f8;
      FUN_14001f280(param_1 + 0x48,plVar9,(ulonglong)puVar12);
      FUN_14001e2a0((longlong)param_2,plVar9,puVar12,lVar14);
      if (local_2e0 < 0x10) {
LAB_1400246e3:
        local_2e8 = 0;
        local_2e0 = 0xf;
        local_2f8 = 0;
        local_260 = std::exception::vftable;
        __std_exception_destroy(local_258);
        local_280 = (undefined8 **)std::exception::vftable;
        __std_exception_destroy(local_278);
        if (0xf < uStack_2c0) {
          if ((uStack_2c0 + 1 < 0x1000) || ((local_2d8 - *(longlong *)(local_2d8 - 8)) - 8 < 0x20))
          {
            FUN_14002f180();
            goto LAB_140024756;
          }
          goto LAB_140024d60;
        }
LAB_140024756:
        if (uStack_80 < 0x10) {
LAB_140024797:
          local_88 = 0;
          uStack_80 = 0xf;
          local_98 = (char *******)((ulonglong)local_98 & 0xffffffffffffff00);
          if (0xf < local_228) {
            if ((0xfff < local_228 + 1) &&
               (0x1f < (local_240[0] - *(longlong *)(local_240[0] + -8)) - 8U)) {
              FUN_140035d28();
              pcVar4 = (code *)swi(3);
              (*pcVar4)();
              return;
            }
            goto LAB_140024aff;
          }
          goto LAB_140024ce2;
        }
        if ((uStack_80 + 1 < 0x1000) ||
           ((char *)((longlong)local_98 + (-8 - (longlong)local_98[-1])) < (char *)0x20)) {
          FUN_14002f180();
          goto LAB_140024797;
        }
      }
      else {
        if ((local_2e0 + 1 < 0x1000) ||
           ((CONCAT71(uStack_2f7,local_2f8) - *(longlong *)(CONCAT71(uStack_2f7,local_2f8) + -8)) -
            8U < 0x20)) {
          FUN_14002f180();
          goto LAB_1400246e3;
        }
LAB_140024d5a:
        FUN_140035d28();
LAB_140024d60:
        FUN_140035d28();
      }
      FUN_140035d28();
LAB_140024d6c:
      FUN_140035d28();
LAB_140024d72:
      FUN_140035d28();
LAB_140024d78:
      FUN_140035d28();
LAB_140024d7e:
      FUN_140035d28();
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    local_98 = (char *******)ppppppppcVar19;
    if (param_2[1] == param_2[2]) {
      pcVar8 = (char *)*param_2;
      local_200[0] = *pcVar8;
      *pcVar8 = '\a';
      local_1f8 = *(undefined8 *)(pcVar8 + 8);
      *(char *********)(pcVar8 + 8) = ppppppppcVar19;
      FUN_14001cf70(local_200);
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        puVar15 = (undefined1 *)plVar9[1];
        if (puVar15 == (undefined1 *)plVar9[2]) {
          param_3 = (char ****)&local_98;
          FUN_1400292e0(plVar9,puVar15,param_3);
        }
        else {
          *puVar15 = 7;
          *(char *********)(puVar15 + 8) = ppppppppcVar19;
          plVar9[1] = plVar9[1] + 0x10;
        }
      }
      else {
        pcVar8 = (char *)param_2[4];
        local_1f0[0] = *pcVar8;
        *pcVar8 = '\a';
        local_1e8 = *(undefined8 *)(pcVar8 + 8);
        *(char *********)(pcVar8 + 8) = ppppppppcVar19;
        FUN_14001cf70(local_1f0);
      }
    }
    break;
  case 8:
    local_a8[0] = '\x02';
    if (param_2[1] == param_2[2]) {
      pcVar8 = (char *)FUN_14001de50(local_d8,'\x02');
      param_3 = (char ****)*param_2;
      cVar1 = *(char *)param_3;
      *(char *)param_3 = *pcVar8;
      *pcVar8 = cVar1;
      pppppppcVar2 = ((char ********)param_3)[1];
      ((char ********)param_3)[1] = *(char ********)(pcVar8 + 8);
      *(char ********)(pcVar8 + 8) = pppppppcVar2;
      FUN_14001cf70(pcVar8);
      local_98 = (char *******)*param_2;
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        pcVar8 = (char *)plVar9[1];
        if (pcVar8 == (char *)plVar9[2]) {
          param_3 = (char ****)local_a8;
          FUN_140028e40(plVar9,(undefined8 *)pcVar8,(char *)param_3);
        }
        else {
          FUN_14001de50(pcVar8,'\x02');
          plVar9[1] = plVar9[1] + 0x10;
        }
        local_98 = (char *******)
                   (*(longlong *)(*(longlong *)(*(longlong *)(param_2[2] + -8) + 8) + 8) + -0x10);
      }
      else {
        pcVar8 = (char *)FUN_14001de50(local_c8,'\x02');
        param_3 = (char ****)param_2[4];
        cVar1 = *(char *)param_3;
        *(char *)param_3 = *pcVar8;
        *pcVar8 = cVar1;
        pppppppcVar2 = ((char ********)param_3)[1];
        ((char ********)param_3)[1] = *(char ********)(pcVar8 + 8);
        *(char ********)(pcVar8 + 8) = pppppppcVar2;
        FUN_14001cf70(pcVar8);
        local_98 = (char *******)param_2[4];
      }
    }
    puVar3 = (undefined8 *)param_2[2];
    if (puVar3 == (undefined8 *)param_2[3]) {
      param_3 = (char ****)&local_98;
      FUN_1400284e0(param_2 + 1,puVar3,param_3);
    }
    else {
      *puVar3 = local_98;
      param_2[2] = param_2[2] + 8;
    }
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 != 10) {
      local_a8[0] = '\x01';
      if ((local_78[3] < 0) && (local_78[3] != 0)) {
        lVar14 = -(((ulonglong)~local_78[3] >> 5) * 4 + 4);
      }
      else {
        lVar14 = ((ulonglong)local_78[3] >> 5) * 4;
      }
      local_1a8 = (char *******)(local_78[0] + lVar14);
      uStack_1a0 = (ulonglong)((uint)local_78[3] & 0x1f);
      param_3 = (char ****)&local_98;
      local_98 = local_1a8;
      uStack_90 = uStack_1a0;
      FUN_1400214b0(local_78,&local_2b8,param_3,param_4,local_a8);
      goto LAB_1400237e0;
    }
    param_2[2] = param_2[2] + -8;
    break;
  case 9:
    local_a8[0] = '\x01';
    if (param_2[1] == param_2[2]) {
      pcVar8 = (char *)FUN_14001de50(local_f8,'\x01');
      param_3 = (char ****)*param_2;
      cVar1 = *(char *)param_3;
      *(char *)param_3 = *pcVar8;
      *pcVar8 = cVar1;
      pppppppcVar2 = ((char ********)param_3)[1];
      ((char ********)param_3)[1] = *(char ********)(pcVar8 + 8);
      *(char ********)(pcVar8 + 8) = pppppppcVar2;
      FUN_14001cf70(pcVar8);
      local_98 = (char *******)*param_2;
    }
    else {
      pcVar8 = *(char **)(param_2[2] + -8);
      if (*pcVar8 == '\x02') {
        plVar9 = *(longlong **)(pcVar8 + 8);
        pcVar8 = (char *)plVar9[1];
        if (pcVar8 == (char *)plVar9[2]) {
          param_3 = (char ****)local_a8;
          FUN_140028e40(plVar9,(undefined8 *)pcVar8,(char *)param_3);
        }
        else {
          FUN_14001de50(pcVar8,'\x01');
          plVar9[1] = plVar9[1] + 0x10;
        }
        local_98 = (char *******)
                   (*(longlong *)(*(longlong *)(*(longlong *)(param_2[2] + -8) + 8) + 8) + -0x10);
      }
      else {
        pcVar8 = (char *)FUN_14001de50(local_e8,'\x01');
        param_3 = (char ****)param_2[4];
        cVar1 = *(char *)param_3;
        *(char *)param_3 = *pcVar8;
        *pcVar8 = cVar1;
        pppppppcVar2 = ((char ********)param_3)[1];
        ((char ********)param_3)[1] = *(char ********)(pcVar8 + 8);
        *(char ********)(pcVar8 + 8) = pppppppcVar2;
        FUN_14001cf70(pcVar8);
        local_98 = (char *******)param_2[4];
      }
    }
    puVar3 = (undefined8 *)param_2[2];
    if (puVar3 == (undefined8 *)param_2[3]) {
      param_3 = (char ****)&local_98;
      FUN_1400284e0(param_2 + 1,puVar3,param_3);
    }
    else {
      *puVar3 = local_98;
      param_2[2] = param_2[2] + 8;
    }
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 0xb) {
      param_2[2] = param_2[2] + -8;
      break;
    }
    if (*(int *)(param_1 + 0x40) == 4) {
      plVar9 = FUN_140028680(*(longlong **)(*(longlong *)(param_2[2] + -8) + 8),local_b8,
                             (undefined8 *)(param_1 + 0x90));
      param_2[4] = *plVar9 + 0x40;
      iVar7 = FUN_14001ef90(param_1);
      if (iVar7 == 0xc) goto code_r0x000140023965;
      local_88 = 0;
      uStack_80 = 0xf;
      local_98 = (char *******)0x0;
      FUN_1400106a0((longlong *)&local_98,(undefined8 *)"object separator",0x10);
      plVar9 = (longlong *)&local_2f8;
      plVar11 = FUN_14001e680(param_1,plVar9,0xc,&local_98);
      local_2b8 = *(longlong *)(param_1 + 0x60);
      uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
      local_2a8 = *(undefined8 *)(param_1 + 0x70);
      plVar13 = &local_2b8;
      lVar14 = FUN_1400186d0(&local_280,plVar9,plVar13,plVar11);
      puVar12 = &local_2d8;
      FUN_14001f280(param_1 + 0x48,(longlong *)puVar12,(ulonglong)plVar13);
      FUN_14001e2a0((longlong)param_2,puVar12,plVar13,lVar14);
      if (0xf < uStack_2c0) {
        if ((uStack_2c0 + 1 < 0x1000) || ((local_2d8 - *(longlong *)(local_2d8 - 8)) - 8 < 0x20)) {
          FUN_14002f180();
          goto LAB_1400242bf;
        }
        goto LAB_140024d42;
      }
LAB_1400242bf:
      local_2c8 = 0;
      uStack_2c0 = 0xf;
      local_2d8 = local_2d8 & 0xffffffffffffff00;
      local_260 = std::exception::vftable;
      __std_exception_destroy(local_258);
      local_280 = (undefined8 **)std::exception::vftable;
      __std_exception_destroy(local_278);
      if (0xf < local_2e0) {
        if ((local_2e0 + 1 < 0x1000) ||
           ((CONCAT71(uStack_2f7,local_2f8) - *(longlong *)(CONCAT71(uStack_2f7,local_2f8) + -8)) -
            8U < 0x20)) {
          FUN_14002f180();
          goto LAB_140024331;
        }
LAB_140024d48:
        FUN_140035d28();
        goto LAB_140024d4e;
      }
LAB_140024331:
      local_2e8 = 0;
      local_2e0 = 0xf;
      local_2f8 = 0;
      if (0xf < uStack_80) {
        if ((0xfff < uStack_80 + 1) &&
           ((char *)0x1f < (char *)((longlong)local_98 + (-8 - (longlong)local_98[-1]))))
        goto LAB_140024d2a;
        goto LAB_140024aff;
      }
      goto LAB_140024ce2;
    }
    local_88 = 0;
    uStack_80 = 0xf;
    local_98 = (char *******)0x0;
    FUN_1400106a0((longlong *)&local_98,(undefined8 *)"object key",10);
    puVar12 = &local_2d8;
    plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,4,&local_98);
    local_2b8 = *(longlong *)(param_1 + 0x60);
    uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
    local_2a8 = *(undefined8 *)(param_1 + 0x70);
    plVar9 = &local_2b8;
    lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
    plVar13 = (longlong *)&local_2f8;
    FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
    FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
    if (local_2e0 < 0x10) {
LAB_140024463:
      local_2e8 = 0;
      local_2e0 = 0xf;
      local_2f8 = 0;
      local_260 = std::exception::vftable;
      __std_exception_destroy(local_258);
      local_280 = (undefined8 **)std::exception::vftable;
      __std_exception_destroy(local_278);
      if (uStack_2c0 < 0x10) {
LAB_1400244d5:
        local_2c8 = 0;
        uStack_2c0 = 0xf;
        local_2d8 = local_2d8 & 0xffffffffffffff00;
        if (0xf < uStack_80) {
          if ((0xfff < uStack_80 + 1) &&
             ((char *)0x1f < (char *)((longlong)local_98 + (-8 - (longlong)local_98[-1])))) {
            FUN_140035d28();
            pcVar4 = (code *)swi(3);
            (*pcVar4)();
            return;
          }
          goto LAB_140024aff;
        }
        goto LAB_140024ce2;
      }
      if ((uStack_2c0 + 1 < 0x1000) || ((local_2d8 - *(longlong *)(local_2d8 - 8)) - 8 < 0x20)) {
        FUN_14002f180();
        goto LAB_1400244d5;
      }
    }
    else {
      if ((local_2e0 + 1 < 0x1000) ||
         ((CONCAT71(uStack_2f7,local_2f8) - *(longlong *)(CONCAT71(uStack_2f7,local_2f8) + -8)) - 8U
          < 0x20)) {
        FUN_14002f180();
        goto LAB_140024463;
      }
LAB_140024d4e:
      FUN_140035d28();
    }
    FUN_140035d28();
    goto LAB_140024d5a;
  default:
    local_290 = 0;
    local_288 = 0xf;
    local_2a0[0] = 0;
    FUN_1400106a0(local_2a0,(undefined8 *)"value",5);
    puVar12 = &local_2d8;
    plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,0x10,local_2a0);
    local_2b8 = *(longlong *)(param_1 + 0x60);
    uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
    local_2a8 = *(undefined8 *)(param_1 + 0x70);
    plVar9 = &local_2b8;
    lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
    plVar13 = (longlong *)&local_2f8;
    FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
    FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
    if (0xf < local_2e0) {
      if ((0xfff < local_2e0 + 1) &&
         (0x1f < (CONCAT71(uStack_2f7,local_2f8) -
                 *(longlong *)(CONCAT71(uStack_2f7,local_2f8) + -8)) - 8U)) goto LAB_140024d78;
      FUN_14002f180();
    }
    local_2e8 = 0;
    local_2e0 = 0xf;
    local_2f8 = 0;
    local_260 = std::exception::vftable;
    __std_exception_destroy(local_258);
    local_280 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_278);
    if (0xf < uStack_2c0) {
      if ((0xfff < uStack_2c0 + 1) && (0x1f < (local_2d8 - *(longlong *)(local_2d8 - 8)) - 8))
      goto LAB_140024d7e;
      FUN_14002f180();
    }
    local_2c8 = 0;
    uStack_2c0 = 0xf;
    local_2d8 = local_2d8 & 0xffffffffffffff00;
    if (0xf < local_288) {
      if ((0xfff < local_288 + 1) && (0x1f < (local_2a0[0] - *(longlong *)(local_2a0[0] + -8)) - 8U)
         ) {
        FUN_140035d28();
LAB_140024d2a:
        FUN_140035d28();
        pcVar4 = (code *)swi(3);
        (*pcVar4)();
        return;
      }
      goto LAB_140024aff;
    }
    goto LAB_140024ce2;
  case 0xe:
    local_290 = 0;
    local_288 = 0xf;
    local_2a0[0] = 0;
    FUN_1400106a0(local_2a0,(undefined8 *)"value",5);
    puVar12 = &local_2d8;
    plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,0,local_2a0);
    local_2b8 = *(longlong *)(param_1 + 0x60);
    uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
    local_2a8 = *(undefined8 *)(param_1 + 0x70);
    plVar9 = &local_2b8;
    lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
    plVar13 = (longlong *)&local_2f8;
    FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
    FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
    if (0xf < local_2e0) {
      if ((local_2e0 + 1 < 0x1000) ||
         ((CONCAT71(uStack_2f7,local_2f8) - *(longlong *)(CONCAT71(uStack_2f7,local_2f8) + -8)) - 8U
          < 0x20)) {
        FUN_14002f180();
        goto LAB_1400248b4;
      }
      goto LAB_140024d6c;
    }
LAB_1400248b4:
    local_2e8 = 0;
    local_2e0 = 0xf;
    local_2f8 = 0;
    local_260 = std::exception::vftable;
    __std_exception_destroy(local_258);
    local_280 = (undefined8 **)std::exception::vftable;
    __std_exception_destroy(local_278);
    if (0xf < uStack_2c0) {
      if ((uStack_2c0 + 1 < 0x1000) || ((local_2d8 - *(longlong *)(local_2d8 - 8)) - 8 < 0x20)) {
        FUN_14002f180();
        goto LAB_140024926;
      }
      goto LAB_140024d72;
    }
LAB_140024926:
    local_2c8 = 0;
    uStack_2c0 = 0xf;
    local_2d8 = local_2d8 & 0xffffffffffffff00;
    if (0xf < local_288) {
      if ((0xfff < local_288 + 1) && (0x1f < (local_2a0[0] - *(longlong *)(local_2a0[0] + -8)) - 8U)
         ) {
        FUN_140035d28();
LAB_140024d42:
        FUN_140035d28();
        goto LAB_140024d48;
      }
LAB_140024aff:
      FUN_14002f180();
    }
    goto LAB_140024ce2;
  }
LAB_140024017:
  if (local_78[3] == 0) goto LAB_140024ce2;
  if ((local_78[3] < 0) && (local_78[3] != 0)) {
    lVar14 = -(((ulonglong)~local_78[3] >> 5) * 4 + 4);
  }
  else {
    lVar14 = ((ulonglong)local_78[3] >> 5) * 4;
  }
  uVar16 = (ulonglong)((uint)local_78[3] & 0x1f);
  uVar17 = uVar16 - 1;
  if (uVar16 == 0) {
    local_108 = -((~uVar17 >> 5) * 4 + 4);
  }
  else {
    local_108 = (uVar17 >> 5) * 4;
  }
  local_108 = local_78[0] + lVar14 + local_108;
  local_100 = (ulonglong)((uint)uVar17 & 0x1f);
  uVar10 = FUN_140024f50(&local_108);
  if ((char)uVar10 == '\0') {
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 0xd) {
      iVar7 = FUN_14001ef90(param_1);
      if (iVar7 != 4) {
        FUN_14000e950(local_240,(undefined8 *)"object key");
        puVar12 = &local_2d8;
        plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,4,local_240);
        local_2b8 = *(longlong *)(param_1 + 0x60);
        uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
        local_2a8 = *(undefined8 *)(param_1 + 0x70);
        plVar9 = &local_2b8;
        lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
        plVar13 = (longlong *)&local_2f8;
        FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
        FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
        FUN_14000e8f0((longlong *)&local_2f8);
        FUN_140018e30(&local_280);
        FUN_14000e8f0((longlong *)&local_2d8);
        FUN_14000e8f0(local_240);
        goto LAB_140024ce2;
      }
      uVar10 = FUN_140024fb0((longlong)param_2,(undefined8 *)(param_1 + 0x90));
      if ((char)uVar10 == '\0') goto LAB_140024ce2;
      iVar7 = FUN_14001ef90(param_1);
      if (iVar7 != 0xc) {
        FUN_14000e950(local_240,(undefined8 *)"object separator");
        puVar12 = &local_2d8;
        plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,0xc,local_240);
        local_2b8 = *(longlong *)(param_1 + 0x60);
        uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
        local_2a8 = *(undefined8 *)(param_1 + 0x70);
        plVar9 = &local_2b8;
        lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
        plVar13 = (longlong *)&local_2f8;
        FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
        FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
        FUN_14000e8f0((longlong *)&local_2f8);
        FUN_140018e30(&local_280);
        FUN_14000e8f0((longlong *)&local_2d8);
        FUN_14000e8f0(local_240);
LAB_140024ce2:
        FUN_14001f390(local_78);
        FUN_14002f160(local_78[4] ^ (ulonglong)auStackY_328);
        return;
      }
      FUN_14001ef90(param_1);
      goto LAB_1400237e0;
    }
    if (*(int *)(param_1 + 0x40) != 0xb) {
      FUN_14000e950(local_240,(undefined8 *)"object");
      puVar12 = &local_2d8;
      plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,0xb,local_240);
      local_2b8 = *(longlong *)(param_1 + 0x60);
      uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
      local_2a8 = *(undefined8 *)(param_1 + 0x70);
      plVar9 = &local_2b8;
      lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
      plVar13 = (longlong *)&local_2f8;
      FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
      FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
      FUN_14000e8f0((longlong *)&local_2f8);
      FUN_140018e30(&local_280);
      FUN_14000e8f0((longlong *)&local_2d8);
      FUN_14000e8f0(local_240);
      goto LAB_140024ce2;
    }
  }
  else {
    iVar7 = FUN_14001ef90(param_1);
    if (iVar7 == 0xd) {
      FUN_14001ef90(param_1);
      goto LAB_1400237e0;
    }
    if (*(int *)(param_1 + 0x40) != 10) {
      FUN_14000e950(local_240,(undefined8 *)"array");
      puVar12 = &local_2d8;
      plVar13 = FUN_14001e680(param_1,(longlong *)puVar12,10,local_240);
      local_2b8 = *(longlong *)(param_1 + 0x60);
      uStack_2b0 = *(undefined8 *)(param_1 + 0x68);
      local_2a8 = *(undefined8 *)(param_1 + 0x70);
      plVar9 = &local_2b8;
      lVar14 = FUN_1400186d0(&local_280,puVar12,plVar9,plVar13);
      plVar13 = (longlong *)&local_2f8;
      FUN_14001f280(param_1 + 0x48,plVar13,(ulonglong)plVar9);
      FUN_14001e2a0((longlong)param_2,plVar13,plVar9,lVar14);
      FUN_14000e8f0((longlong *)&local_2f8);
      FUN_140018e30(&local_280);
      FUN_14000e8f0((longlong *)&local_2d8);
      FUN_14000e8f0(local_240);
      goto LAB_140024ce2;
    }
  }
  param_2[2] = param_2[2] + -8;
  FUN_140025870(local_78);
  bVar5 = true;
  goto LAB_1400237e0;
code_r0x000140023965:
  local_a8[0] = '\0';
  if ((local_78[3] < 0) && (local_78[3] != 0)) {
    lVar14 = -(((ulonglong)~local_78[3] >> 5) * 4 + 4);
  }
  else {
    lVar14 = ((ulonglong)local_78[3] >> 5) * 4;
  }
  local_1b8 = (char *******)(local_78[0] + lVar14);
  uStack_1b0 = (ulonglong)((uint)local_78[3] & 0x1f);
  param_3 = (char ****)&local_98;
  local_98 = local_1b8;
  uStack_90 = uStack_1b0;
  FUN_1400214b0(local_78,local_2a0,param_3,param_4,local_a8);
  FUN_14001ef90(param_1);
  goto LAB_1400237e0;
}


// FUNCTION_END

// FUNCTION_START: FUN_140024dc0 @ 140024dc0