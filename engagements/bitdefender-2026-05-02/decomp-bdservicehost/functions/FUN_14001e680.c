longlong * FUN_14001e680(longlong param_1,longlong *param_2,int param_3,undefined8 *param_4)

{
  code *pcVar1;
  char ****ppppcVar2;
  ulonglong uVar3;
  char ****ppppcVar4;
  longlong *plVar5;
  undefined8 *puVar6;
  char *pcVar7;
  undefined8 *****pppppuVar8;
  undefined8 *****pppppuVar9;
  __uint64 _Var10;
  char *****pppppcVar11;
  char *****pppppcVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  __uint64 _Var15;
  char ****local_110 [2];
  ulonglong local_100;
  ulonglong uStack_f8;
  int local_f0;
  undefined8 ****local_e8;
  char ***pppcStack_e0;
  char ***local_d8;
  char ***pppcStack_d0;
  ulonglong local_c8;
  longlong local_c0;
  undefined8 ****local_b8;
  longlong lStack_b0;
  ulonglong local_a8;
  ulonglong uStack_a0;
  undefined8 ****local_98;
  longlong lStack_90;
  ulonglong local_88;
  ulonglong uStack_80;
  longlong *local_78;
  longlong local_70 [3];
  ulonglong local_58;
  
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0xf;
  *(undefined1 *)param_2 = 0;
  puVar6 = param_4;
  local_f0 = param_3;
  local_c0 = param_1;
  local_78 = param_2;
  FUN_1400106a0(param_2,(undefined8 *)"syntax error ",0xd);
  local_c8 = param_4[2];
  _Var10 = 0xffffffffffffffff;
  if (local_c8 != 0) {
    if (0x7fffffffffffffff - local_c8 < 0xe) {
      FUN_140001a20();
      pcVar1 = (code *)swi(3);
      plVar5 = (longlong *)(*pcVar1)();
      return plVar5;
    }
    if (0xf < (ulonglong)param_4[3]) {
      param_4 = (undefined8 *)*param_4;
    }
    local_110[0] = (char ****)0x0;
    local_100 = 0;
    uStack_f8 = 0;
    uVar14 = local_c8 + 0xe;
    uVar13 = 0xf;
    pppppcVar11 = local_110;
    if (uVar14 < 0x10) {
LAB_14001e7cc:
      uVar3 = local_c8;
      local_100 = uVar14;
      uStack_f8 = uVar13;
      *pppppcVar11 = (char ****)s_while_parsing_14006c9b8._0_8_;
      *(undefined4 *)(pppppcVar11 + 1) = s_while_parsing_14006c9b8._8_4_;
      *(undefined2 *)((longlong)pppppcVar11 + 0xc) = s_while_parsing_14006c9b8._12_2_;
      FUN_1400316b0((undefined8 *)((longlong)pppppcVar11 + 0xe),param_4,uVar3);
      *(char *)((longlong)pppppcVar11 + uVar14) = '\0';
      plVar5 = FUN_140010800((longlong *)local_110,(undefined8 *)&DAT_14006b340,1);
      local_b8 = (undefined8 ****)*plVar5;
      lStack_b0 = plVar5[1];
      local_a8 = plVar5[2];
      uStack_a0 = plVar5[3];
      plVar5[2] = 0;
      plVar5[3] = 0xf;
      *(undefined1 *)plVar5 = 0;
      pppppuVar8 = &local_b8;
      if (0xf < uStack_a0) {
        pppppuVar8 = (undefined8 *****)local_b8;
      }
      FUN_140010800(param_2,pppppuVar8,local_a8);
      if (0xf < uStack_a0) {
        if ((0xfff < uStack_a0 + 1) &&
           (0x1f < (ulonglong)((longlong)local_b8 + (-8 - (longlong)local_b8[-1])))) {
LAB_14001ef4c:
          FUN_140035d28();
          goto LAB_14001ef52;
        }
        FUN_14002f180();
      }
      param_1 = local_c0;
      if (0xf < uStack_f8) {
        if ((0xfff < uStack_f8 + 1) &&
           ((char *)0x1f < (char *)((longlong)local_110[0] + (-8 - (longlong)local_110[0][-1]))))
        goto LAB_14001ef52;
        FUN_14002f180();
        param_1 = local_c0;
      }
      goto LAB_14001e8ff;
    }
    uVar13 = uVar14;
    if (uVar14 < 0x10) {
      uVar13 = DAT_14006dad8;
    }
    uVar13 = uVar13 | 0xf;
    if (uVar13 < 0x8000000000000000) {
      if (uVar13 < 0x16) {
        uVar13 = 0x16;
      }
    }
    else {
      uVar13 = 0x7fffffffffffffff;
    }
    _Var15 = uVar13 + 1;
    if (uVar13 == 0xffffffffffffffff) {
      _Var15 = _Var10;
    }
    if (_Var15 < 0x1000) {
      if (_Var15 == 0) {
        pppppcVar11 = (char *****)0x0;
        local_110[0] = (char ****)pppppcVar11;
      }
      else {
        pppppcVar11 = (char *****)operator_new(_Var15);
        local_110[0] = (char ****)pppppcVar11;
      }
      goto LAB_14001e7cc;
    }
    if (_Var15 + 0x27 <= _Var15) {
      FUN_140001670();
      goto LAB_14001ef4c;
    }
    ppppcVar4 = (char ****)operator_new(_Var15 + 0x27);
    if (ppppcVar4 != (char ****)0x0) {
      pppppcVar11 = (char *****)((longlong)ppppcVar4 + 0x27U & 0xffffffffffffffe0);
      pppppcVar11[-1] = ppppcVar4;
      local_110[0] = (char ****)pppppcVar11;
      goto LAB_14001e7cc;
    }
LAB_14001ef52:
    FUN_140035d28();
LAB_14001ef58:
    FUN_140035d28();
LAB_14001ef5e:
    FUN_140035d28();
LAB_14001ef64:
    FUN_140035d28();
LAB_14001ef6a:
    FUN_140035d28();
LAB_14001ef70:
    FUN_140035d28();
LAB_14001ef76:
    FUN_140035d28();
    goto LAB_14001ef7c;
  }
LAB_14001e8ff:
  uVar14 = 2;
  FUN_140010800(param_2,(undefined8 *)&DAT_14006c9c8,2);
  if (*(int *)(param_1 + 0x40) == 0xe) {
    puVar6 = (undefined8 *)FUN_14001f280(param_1 + 0x48,local_70,uVar14);
    local_100 = 0;
    uStack_f8 = 0xf;
    local_110[0] = (char ****)0x0;
    _Var15 = _Var10;
    do {
      _Var15 = _Var15 + 1;
    } while (*(char *)((longlong)*(undefined8 **)(param_1 + 0xb0) + _Var15) != '\0');
    FUN_1400106a0((longlong *)local_110,*(undefined8 **)(param_1 + 0xb0),_Var15);
    pcVar7 = "; last read: \'";
    plVar5 = FUN_140010800((longlong *)local_110,(undefined8 *)"; last read: \'",0xe);
    local_e8 = (undefined8 ****)*plVar5;
    pppcStack_e0 = (char ***)plVar5[1];
    local_d8 = (char ***)plVar5[2];
    pppcStack_d0 = (char ***)plVar5[3];
    plVar5[2] = 0;
    plVar5[3] = 0xf;
    *(undefined1 *)plVar5 = 0;
    FUN_140025910(&local_b8,pcVar7,&local_e8,puVar6);
    plVar5 = FUN_140010800((longlong *)&local_b8,(undefined8 *)&DAT_14006c918,1);
    local_98 = (undefined8 ****)*plVar5;
    lStack_90 = plVar5[1];
    local_88 = plVar5[2];
    uStack_80 = plVar5[3];
    plVar5[2] = 0;
    plVar5[3] = 0xf;
    *(undefined1 *)plVar5 = 0;
    pppppuVar8 = &local_98;
    if (0xf < uStack_80) {
      pppppuVar8 = (undefined8 *****)local_98;
    }
    FUN_140010800(param_2,pppppuVar8,local_88);
    if (0xf < uStack_80) {
      if ((0xfff < uStack_80 + 1) &&
         (0x1f < (ulonglong)((longlong)local_98 + (-8 - (longlong)local_98[-1]))))
      goto LAB_14001ef58;
      FUN_14002f180();
    }
    if (0xf < uStack_a0) {
      if ((0xfff < uStack_a0 + 1) &&
         (0x1f < (ulonglong)((longlong)local_b8 + (-8 - (longlong)local_b8[-1]))))
      goto LAB_14001ef5e;
      FUN_14002f180();
    }
    local_a8 = 0;
    uStack_a0 = 0xf;
    local_b8 = (undefined8 ****)((ulonglong)local_b8 & 0xffffffffffffff00);
    if ((char ****)0xf < pppcStack_d0) {
      if ((0xfff < (longlong)pppcStack_d0 + 1U) &&
         (0x1f < (ulonglong)((longlong)local_e8 + (-8 - (longlong)local_e8[-1]))))
      goto LAB_14001ef64;
      FUN_14002f180();
    }
    if (0xf < uStack_f8) {
      if ((0xfff < uStack_f8 + 1) &&
         ((char *)0x1f < (char *)((longlong)local_110[0] + (-8 - (longlong)local_110[0][-1]))))
      goto LAB_14001ef6a;
      FUN_14002f180();
    }
    local_100 = 0;
    uStack_f8 = 0xf;
    local_110[0] = (char ****)((ulonglong)local_110[0] & 0xffffffffffffff00);
    if (0xf < local_58) {
      if ((0xfff < local_58 + 1) && (0x1f < (local_70[0] - *(longlong *)(local_70[0] + -8)) - 8U)) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        plVar5 = (longlong *)(*pcVar1)();
        return plVar5;
      }
LAB_14001ed4c:
      FUN_14002f180();
    }
  }
  else {
    pcVar7 = FUN_14001f6d0(*(int *)(param_1 + 0x40));
    local_100 = 0;
    uStack_f8 = 0xf;
    local_110[0] = (char ****)0x0;
    _Var15 = _Var10;
    do {
      _Var15 = _Var15 + 1;
    } while (pcVar7[_Var15] != '\0');
    FUN_1400106a0((longlong *)local_110,(undefined8 *)pcVar7,_Var15);
    if (uStack_f8 - local_100 < 0xb) {
      pppppcVar11 = (char *****)
                    FUN_140014ae0(local_110,0xb,local_100,puVar6,(undefined8 *)"unexpected ",0xb);
    }
    else {
      pppppcVar11 = local_110;
      if (0xf < uStack_f8) {
        pppppcVar11 = (char *****)local_110[0];
      }
      if (((char *****)0x14006c9ea < pppppcVar11) ||
         ((char *)((longlong)pppppcVar11 + local_100) < "unexpected ")) {
        pppppcVar12 = (char *****)0xb;
      }
      else if ("unexpected " < pppppcVar11) {
        pppppcVar12 = pppppcVar11 + -0x2800d93c;
      }
      else {
        pppppcVar12 = (char *****)0x0;
      }
      uVar14 = local_100 + 1;
      local_100 = local_100 + 0xb;
      FUN_1400316b0((undefined8 *)((longlong)pppppcVar11 + 0xb),pppppcVar11,uVar14);
      FUN_1400316b0(pppppcVar11,(undefined8 *)"unexpected ",(ulonglong)pppppcVar12);
      FUN_1400316b0((undefined8 *)((longlong)pppppcVar11 + (longlong)pppppcVar12),
                    (undefined8 *)((longlong)pppppcVar12 + 0x14006c9eb),0xb - (longlong)pppppcVar12)
      ;
      pppppcVar11 = local_110;
    }
    pppppuVar8 = (undefined8 *****)*pppppcVar11;
    local_e8 = pppppuVar8;
    pppcStack_e0 = (char ***)pppppcVar11[1];
    ppppcVar4 = pppppcVar11[2];
    ppppcVar2 = pppppcVar11[3];
    local_d8 = (char ***)ppppcVar4;
    pppcStack_d0 = (char ***)ppppcVar2;
    pppppcVar11[2] = (char ****)0x0;
    pppppcVar11[3] = (char ****)0xf;
    *(undefined1 *)pppppcVar11 = 0;
    pppppuVar9 = &local_e8;
    if ((char ****)0xf < ppppcVar2) {
      pppppuVar9 = pppppuVar8;
    }
    FUN_140010800(param_2,pppppuVar9,(ulonglong)ppppcVar4);
    if ((char ****)0xf < pppcStack_d0) {
      if ((0xfff < (longlong)pppcStack_d0 + 1U) &&
         (0x1f < (ulonglong)((longlong)local_e8 + (-8 - (longlong)local_e8[-1]))))
      goto LAB_14001ef70;
      FUN_14002f180();
    }
    if (0xf < uStack_f8) {
      if ((0xfff < uStack_f8 + 1) &&
         ((char *)0x1f < (char *)((longlong)local_110[0] + (-8 - (longlong)local_110[0][-1]))))
      goto LAB_14001ef76;
      goto LAB_14001ed4c;
    }
  }
  pppppcVar11 = (char *****)0x0;
  if (local_f0 != 0) {
    pcVar7 = FUN_14001f6d0(local_f0);
    local_100 = 0;
    uStack_f8 = 0xf;
    local_110[0] = (char ****)0x0;
    do {
      _Var10 = _Var10 + 1;
    } while (pcVar7[_Var10] != '\0');
    FUN_1400106a0((longlong *)local_110,(undefined8 *)pcVar7,_Var10);
    if (uStack_f8 - local_100 < 0xb) {
      pppppcVar11 = (char *****)
                    FUN_140014ae0(local_110,0xb,local_100,puVar6,(undefined8 *)"; expected ",0xb);
    }
    else {
      pppppcVar12 = local_110;
      if (0xf < uStack_f8) {
        pppppcVar12 = (char *****)local_110[0];
      }
      if (((char *****)0x14006c9fa < pppppcVar12) ||
         ((char *)((longlong)pppppcVar12 + local_100) < "; expected ")) {
        pppppcVar11 = (char *****)0xb;
      }
      else if ("; expected " < pppppcVar12) {
        pppppcVar11 = pppppcVar12 + -0x2800d93e;
      }
      uVar14 = local_100 + 1;
      local_100 = local_100 + 0xb;
      FUN_1400316b0((undefined8 *)((longlong)pppppcVar12 + 0xb),pppppcVar12,uVar14);
      FUN_1400316b0(pppppcVar12,(undefined8 *)"; expected ",(ulonglong)pppppcVar11);
      FUN_1400316b0((undefined8 *)((longlong)pppppcVar12 + (longlong)pppppcVar11),
                    (undefined8 *)((longlong)pppppcVar11 + 0x14006c9fb),0xb - (longlong)pppppcVar11)
      ;
      pppppcVar11 = local_110;
    }
    pppppuVar8 = (undefined8 *****)*pppppcVar11;
    local_e8 = pppppuVar8;
    pppcStack_e0 = (char ***)pppppcVar11[1];
    ppppcVar4 = pppppcVar11[2];
    ppppcVar2 = pppppcVar11[3];
    local_d8 = (char ***)ppppcVar4;
    pppcStack_d0 = (char ***)ppppcVar2;
    pppppcVar11[2] = (char ****)0x0;
    pppppcVar11[3] = (char ****)0xf;
    *(undefined1 *)pppppcVar11 = 0;
    pppppuVar9 = &local_e8;
    if ((char ****)0xf < ppppcVar2) {
      pppppuVar9 = pppppuVar8;
    }
    FUN_140010800(param_2,pppppuVar9,(ulonglong)ppppcVar4);
    if ((char ****)0xf < pppcStack_d0) {
      if ((0xfff < (longlong)pppcStack_d0 + 1U) &&
         (0x1f < (ulonglong)((longlong)local_e8 + (-8 - (longlong)local_e8[-1])))) {
LAB_14001ef7c:
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        plVar5 = (longlong *)(*pcVar1)();
        return plVar5;
      }
      FUN_14002f180();
    }
    if (0xf < uStack_f8) {
      if ((0xfff < uStack_f8 + 1) &&
         ((char *)0x1f < (char *)((longlong)local_110[0] + (-8 - (longlong)local_110[0][-1])))) {
        FUN_140035d28();
        pcVar1 = (code *)swi(3);
        plVar5 = (longlong *)(*pcVar1)();
        return plVar5;
      }
      FUN_14002f180();
    }
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001ef90 @ 14001ef90