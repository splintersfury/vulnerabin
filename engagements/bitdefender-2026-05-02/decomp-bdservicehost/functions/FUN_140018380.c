longlong * FUN_140018380(longlong *param_1,undefined8 *param_2,uint param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  longlong lVar4;
  char *******pppppppcVar5;
  undefined8 *puVar6;
  char ******ppppppcVar7;
  longlong *plVar8;
  __uint64 _Var9;
  undefined *puVar10;
  ulonglong uVar11;
  char *******pppppppcVar12;
  char ******local_c8 [2];
  ulonglong local_b8;
  ulonglong local_b0;
  undefined1 local_a8;
  undefined7 uStack_a7;
  undefined8 local_98;
  ulonglong local_90;
  longlong local_88;
  longlong lStack_80;
  longlong local_78;
  ulonglong uStack_70;
  longlong *local_68;
  longlong local_60 [3];
  ulonglong local_48;
  
  local_68 = param_1;
  puVar6 = (undefined8 *)FUN_140017f40(local_60,param_3);
  uVar2 = param_2[2];
  if (0x7fffffffffffffff - uVar2 < 0x10) {
LAB_14001864d:
    FUN_140001a20();
LAB_140018653:
    FUN_140001670();
LAB_140018659:
    FUN_140035d28();
  }
  else {
    if (0xf < (ulonglong)param_2[3]) {
      param_2 = (undefined8 *)*param_2;
    }
    local_c8[0] = (char ******)0x0;
    local_b8 = 0;
    local_b0 = 0;
    uVar1 = uVar2 + 0x10;
    uVar11 = 0xf;
    pppppppcVar12 = local_c8;
    pppppppcVar5 = (char *******)local_c8[0];
    if (0xf < uVar1) {
      uVar11 = uVar1 | 0xf;
      if (uVar11 < 0x8000000000000000) {
        if (uVar11 < 0x16) {
          uVar11 = 0x16;
        }
      }
      else {
        uVar11 = 0x7fffffffffffffff;
      }
      _Var9 = uVar11 + 1;
      if (uVar11 == 0xffffffffffffffff) {
        _Var9 = 0xffffffffffffffff;
      }
      if (_Var9 < 0x1000) {
        pppppppcVar12 = (char *******)0x0;
        pppppppcVar5 = (char *******)0x0;
        if (_Var9 != 0) {
          pppppppcVar12 = (char *******)operator_new(_Var9);
          pppppppcVar5 = pppppppcVar12;
        }
        goto LAB_140018477;
      }
      if (_Var9 < _Var9 + 0x27) {
        ppppppcVar7 = (char ******)operator_new(_Var9 + 0x27);
        if (ppppppcVar7 == (char ******)0x0) goto LAB_140018665;
        pppppppcVar12 = (char *******)((longlong)ppppppcVar7 + 0x27U & 0xffffffffffffffe0);
        pppppppcVar12[-1] = ppppppcVar7;
        pppppppcVar5 = pppppppcVar12;
        goto LAB_140018477;
      }
      goto LAB_140018653;
    }
LAB_140018477:
    local_c8[0] = (char ******)pppppppcVar5;
    local_b8 = uVar1;
    local_b0 = uVar11;
    *pppppppcVar12 = (char ******)s__json_exception__14006c3c0._0_8_;
    pppppppcVar12[1] = (char ******)s__json_exception__14006c3c0._8_8_;
    FUN_1400316b0(pppppppcVar12 + 2,param_2,uVar2);
    *(char *)((longlong)pppppppcVar12 + uVar1) = '\0';
    puVar10 = &DAT_14006aad8;
    plVar8 = FUN_140010800((longlong *)local_c8,(undefined8 *)&DAT_14006aad8,1);
    local_88 = *plVar8;
    lStack_80 = plVar8[1];
    local_78 = plVar8[2];
    uStack_70 = plVar8[3];
    plVar8[2] = 0;
    plVar8[3] = 0xf;
    *(undefined1 *)plVar8 = 0;
    FUN_140025910((undefined8 *)&local_a8,puVar10,&local_88,puVar6);
    plVar8 = FUN_140010800((longlong *)&local_a8,(undefined8 *)&DAT_14006c3bc,2);
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    lVar4 = plVar8[1];
    *param_1 = *plVar8;
    param_1[1] = lVar4;
    lVar4 = plVar8[3];
    param_1[2] = plVar8[2];
    param_1[3] = lVar4;
    plVar8[2] = 0;
    plVar8[3] = 0xf;
    *(undefined1 *)plVar8 = 0;
    if (0xf < local_90) {
      if ((local_90 + 1 < 0x1000) ||
         ((CONCAT71(uStack_a7,local_a8) - *(longlong *)(CONCAT71(uStack_a7,local_a8) + -8)) - 8U <
          0x20)) {
        FUN_14002f180();
        goto LAB_14001855b;
      }
      goto LAB_140018659;
    }
LAB_14001855b:
    local_98 = 0;
    local_90 = 0xf;
    local_a8 = 0;
    if (uStack_70 < 0x10) {
LAB_1400185a7:
      if (0xf < local_b0) {
        if ((0xfff < local_b0 + 1) &&
           ((char *)0x1f < (char *)((longlong)local_c8[0] + (-8 - (longlong)local_c8[0][-1]))))
        goto LAB_140018665;
        FUN_14002f180();
      }
      local_b8 = 0;
      local_b0 = 0xf;
      local_c8[0] = (char ******)((ulonglong)local_c8[0] & 0xffffffffffffff00);
      if (local_48 < 0x10) {
        return param_1;
      }
      if ((local_48 + 1 < 0x1000) || ((local_60[0] - *(longlong *)(local_60[0] + -8)) - 8U < 0x20))
      {
        FUN_14002f180();
        return param_1;
      }
      FUN_140035d28();
      goto LAB_14001864d;
    }
    if ((uStack_70 + 1 < 0x1000) || ((local_88 - *(longlong *)(local_88 + -8)) - 8U < 0x20)) {
      FUN_14002f180();
      goto LAB_1400185a7;
    }
  }
  FUN_140035d28();
LAB_140018665:
  FUN_140035d28();
  pcVar3 = (code *)swi(3);
  plVar8 = (longlong *)(*pcVar3)();
  return plVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_140018670 @ 140018670