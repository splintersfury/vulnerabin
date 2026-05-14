undefined8 *
FUN_140013af0(undefined8 *param_1,ulonglong param_2,undefined8 param_3,undefined8 *param_4,
             ulonglong param_5)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  code *pcVar6;
  void *pvVar7;
  ulonglong uVar8;
  __uint64 _Var9;
  ulonglong uVar10;
  undefined8 *puVar11;
  
  uVar3 = param_1[2];
  if (0x7fffffffffffffff - uVar3 < param_2) {
    FUN_140001a20();
    pcVar6 = (code *)swi(3);
    puVar11 = (undefined8 *)(*pcVar6)();
    return puVar11;
  }
  uVar4 = param_1[3];
  uVar8 = param_2 + uVar3 | 0xf;
  uVar10 = 0x7fffffffffffffff;
  if (((uVar8 < 0x8000000000000000) && (uVar4 <= 0x7fffffffffffffff - (uVar4 >> 1))) &&
     (uVar1 = (uVar4 >> 1) + uVar4, uVar10 = uVar8, uVar8 < uVar1)) {
    uVar10 = uVar1;
  }
  _Var9 = uVar10 + 1;
  if (uVar10 == 0xffffffffffffffff) {
    _Var9 = 0xffffffffffffffff;
  }
  if (_Var9 < 0x1000) {
    if (_Var9 == 0) {
      puVar11 = (undefined8 *)0x0;
    }
    else {
      puVar11 = (undefined8 *)operator_new(_Var9);
    }
  }
  else {
    if (_Var9 + 0x27 <= _Var9) {
      FUN_140001670();
      pcVar6 = (code *)swi(3);
      puVar11 = (undefined8 *)(*pcVar6)();
      return puVar11;
    }
    pvVar7 = operator_new(_Var9 + 0x27);
    if (pvVar7 == (void *)0x0) goto LAB_140013c6a;
    puVar11 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
    puVar11[-1] = pvVar7;
  }
  param_1[2] = param_2 + uVar3;
  puVar2 = (undefined8 *)((longlong)puVar11 + uVar3);
  param_1[3] = uVar10;
  if (uVar4 < 0x10) {
    FUN_1400316b0(puVar11,param_1,uVar3);
    FUN_1400316b0(puVar2,param_4,param_5);
    *(undefined1 *)((longlong)puVar2 + param_5) = 0;
  }
  else {
    puVar5 = (undefined8 *)*param_1;
    FUN_1400316b0(puVar11,puVar5,uVar3);
    FUN_1400316b0(puVar2,param_4,param_5);
    *(undefined1 *)((longlong)puVar2 + param_5) = 0;
    if ((0xfff < uVar4 + 1) && (0x1f < (ulonglong)((longlong)puVar5 + (-8 - puVar5[-1])))) {
LAB_140013c6a:
      FUN_140035d28();
      pcVar6 = (code *)swi(3);
      puVar11 = (undefined8 *)(*pcVar6)();
      return puVar11;
    }
    FUN_14002f180();
  }
  *param_1 = puVar11;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140013c80 @ 140013c80