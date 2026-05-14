longlong * FUN_1400106a0(longlong *param_1,undefined8 *param_2,ulonglong param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  void *pvVar4;
  longlong *plVar5;
  ulonglong uVar6;
  __uint64 _Var7;
  undefined8 *puVar8;
  ulonglong uVar9;
  
  uVar2 = param_1[3];
  if (param_3 <= uVar2) {
    plVar5 = param_1;
    if (0xf < uVar2) {
      plVar5 = (longlong *)*param_1;
    }
    param_1[2] = param_3;
    FUN_1400316b0(plVar5,param_2,param_3);
    *(undefined1 *)(param_3 + (longlong)plVar5) = 0;
    return param_1;
  }
  if (0x7fffffffffffffff < param_3) {
    FUN_140001a20();
    pcVar3 = (code *)swi(3);
    plVar5 = (longlong *)(*pcVar3)();
    return plVar5;
  }
  uVar6 = param_3 | 0xf;
  uVar9 = 0x7fffffffffffffff;
  if (((uVar6 < 0x8000000000000000) && (uVar2 <= 0x7fffffffffffffff - (uVar2 >> 1))) &&
     (uVar1 = (uVar2 >> 1) + uVar2, uVar9 = uVar6, uVar6 < uVar1)) {
    uVar9 = uVar1;
  }
  _Var7 = uVar9 + 1;
  if (uVar9 == 0xffffffffffffffff) {
    _Var7 = 0xffffffffffffffff;
  }
  if (_Var7 < 0x1000) {
    if (_Var7 == 0) {
      puVar8 = (undefined8 *)0x0;
    }
    else {
      puVar8 = (undefined8 *)operator_new(_Var7);
    }
  }
  else {
    if (_Var7 + 0x27 <= _Var7) {
      FUN_140001670();
      pcVar3 = (code *)swi(3);
      plVar5 = (longlong *)(*pcVar3)();
      return plVar5;
    }
    pvVar4 = operator_new(_Var7 + 0x27);
    if (pvVar4 == (void *)0x0) goto LAB_1400107f0;
    puVar8 = (undefined8 *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
    puVar8[-1] = pvVar4;
  }
  param_1[2] = param_3;
  param_1[3] = uVar9;
  FUN_1400316b0(puVar8,param_2,param_3);
  *(undefined1 *)(param_3 + (longlong)puVar8) = 0;
  if (0xf < uVar2) {
    if ((0xfff < uVar2 + 1) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U)) {
LAB_1400107f0:
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      plVar5 = (longlong *)(*pcVar3)();
      return plVar5;
    }
    FUN_14002f180();
  }
  *param_1 = (longlong)puVar8;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010800 @ 140010800