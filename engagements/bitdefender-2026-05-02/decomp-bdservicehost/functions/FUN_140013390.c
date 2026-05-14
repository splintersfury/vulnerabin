undefined8 * FUN_140013390(undefined8 *param_1,ulonglong param_2)

{
  ulonglong uVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  code *pcVar5;
  void *pvVar6;
  __uint64 _Var7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined8 *puVar10;
  
  lVar2 = param_1[2];
  if (0x7fffffffffffffffU - lVar2 < param_2) {
    FUN_140001a20();
    pcVar5 = (code *)swi(3);
    puVar10 = (undefined8 *)(*pcVar5)();
    return puVar10;
  }
  uVar3 = param_1[3];
  uVar8 = param_2 + lVar2 | 0xf;
  uVar9 = 0x7fffffffffffffff;
  if (((uVar8 < 0x8000000000000000) && (uVar3 <= 0x7fffffffffffffff - (uVar3 >> 1))) &&
     (uVar1 = (uVar3 >> 1) + uVar3, uVar9 = uVar8, uVar8 < uVar1)) {
    uVar9 = uVar1;
  }
  _Var7 = uVar9 + 1;
  if (uVar9 == 0xffffffffffffffff) {
    _Var7 = 0xffffffffffffffff;
  }
  if (_Var7 < 0x1000) {
    if (_Var7 == 0) {
      puVar10 = (undefined8 *)0x0;
    }
    else {
      puVar10 = (undefined8 *)operator_new(_Var7);
    }
  }
  else {
    if (_Var7 + 0x27 <= _Var7) {
      FUN_140001670();
      pcVar5 = (code *)swi(3);
      puVar10 = (undefined8 *)(*pcVar5)();
      return puVar10;
    }
    pvVar6 = operator_new(_Var7 + 0x27);
    if (pvVar6 == (void *)0x0) goto LAB_1400134c8;
    puVar10 = (undefined8 *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
    puVar10[-1] = pvVar6;
  }
  param_1[2] = param_2 + lVar2;
  param_1[3] = uVar9;
  if (uVar3 < 0x10) {
    FUN_1400316b0(puVar10,param_1,lVar2 + 1U);
  }
  else {
    puVar4 = (undefined8 *)*param_1;
    FUN_1400316b0(puVar10,puVar4,lVar2 + 1U);
    if ((0xfff < uVar3 + 1) && (0x1f < (ulonglong)((longlong)puVar4 + (-8 - puVar4[-1])))) {
LAB_1400134c8:
      FUN_140035d28();
      pcVar5 = (code *)swi(3);
      puVar10 = (undefined8 *)(*pcVar5)();
      return puVar10;
    }
    FUN_14002f180();
  }
  *param_1 = puVar10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400134e0 @ 1400134e0