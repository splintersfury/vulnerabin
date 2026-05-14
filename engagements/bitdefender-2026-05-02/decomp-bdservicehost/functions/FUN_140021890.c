undefined8 * FUN_140021890(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  void *pvVar4;
  undefined8 *puVar5;
  __uint64 _Var6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  
  uVar7 = 0xffffffffffffffff;
  do {
    uVar7 = uVar7 + 1;
  } while (*(char *)(uVar7 + (longlong)param_2) != '\0');
  uVar2 = param_3[2];
  if (0x7fffffffffffffff - uVar2 < uVar7) {
    FUN_140001a20();
    pcVar3 = (code *)swi(3);
    puVar5 = (undefined8 *)(*pcVar3)();
    return puVar5;
  }
  if (0xf < (ulonglong)param_3[3]) {
    param_3 = (undefined8 *)*param_3;
  }
  puVar9 = (undefined8 *)0x0;
  uVar1 = uVar2 + uVar7;
  uVar8 = 0xf;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  puVar5 = param_1;
  if (0xf < uVar1) {
    uVar8 = uVar1 | 0xf;
    if (uVar8 < 0x8000000000000000) {
      if (uVar8 < 0x16) {
        uVar8 = 0x16;
      }
    }
    else {
      uVar8 = 0x7fffffffffffffff;
    }
    _Var6 = uVar8 + 1;
    if (uVar8 == 0xffffffffffffffff) {
      _Var6 = 0xffffffffffffffff;
    }
    if (_Var6 < 0x1000) {
      if (_Var6 != 0) {
        puVar9 = (undefined8 *)operator_new(_Var6);
      }
    }
    else {
      if (_Var6 + 0x27 <= _Var6) {
        FUN_140001670();
        pcVar3 = (code *)swi(3);
        puVar5 = (undefined8 *)(*pcVar3)();
        return puVar5;
      }
      pvVar4 = operator_new(_Var6 + 0x27);
      if (pvVar4 == (void *)0x0) {
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        puVar5 = (undefined8 *)(*pcVar3)();
        return puVar5;
      }
      puVar9 = (undefined8 *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
      puVar9[-1] = pvVar4;
    }
    *param_1 = puVar9;
    puVar5 = puVar9;
  }
  param_1[2] = uVar1;
  param_1[3] = uVar8;
  FUN_1400316b0(puVar5,param_2,uVar7);
  FUN_1400316b0((undefined8 *)((longlong)puVar5 + uVar7),param_3,uVar2);
  *(undefined1 *)((longlong)puVar5 + uVar1) = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400219f0 @ 1400219f0