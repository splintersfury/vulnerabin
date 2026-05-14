undefined8 *
FUN_140025910(undefined8 *param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  code *pcVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  void *pvVar7;
  __uint64 _Var8;
  ulonglong uVar9;
  undefined8 *puVar10;
  
  puVar10 = (undefined8 *)0x0;
  *param_1 = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar2 = param_3[2];
  uVar3 = param_4[2];
  uVar1 = uVar3 + uVar2;
  if ((param_3[3] - uVar2 < uVar3) || ((ulonglong)param_3[3] < (ulonglong)param_4[3])) {
    if (param_4[3] - uVar3 < uVar2) {
      if (0x7fffffffffffffff - uVar2 < uVar3) {
        FUN_140001a20();
        pcVar4 = (code *)swi(3);
        puVar10 = (undefined8 *)(*pcVar4)();
        return puVar10;
      }
      uVar6 = uVar1 | 0xf;
      uVar9 = 0x7fffffffffffffff;
      if ((uVar6 < 0x8000000000000000) && (uVar9 = uVar6, uVar6 < 0x16)) {
        uVar9 = 0x16;
      }
      _Var8 = uVar9 + 1;
      if (uVar9 == 0xffffffffffffffff) {
        _Var8 = 0xffffffffffffffff;
      }
      if (_Var8 < 0x1000) {
        if (_Var8 != 0) {
          puVar10 = (undefined8 *)operator_new(_Var8);
        }
      }
      else {
        if (_Var8 + 0x27 <= _Var8) {
          FUN_140001670();
          pcVar4 = (code *)swi(3);
          puVar10 = (undefined8 *)(*pcVar4)();
          return puVar10;
        }
        pvVar7 = operator_new(_Var8 + 0x27);
        if (pvVar7 == (void *)0x0) {
          FUN_140035d28();
          pcVar4 = (code *)swi(3);
          puVar10 = (undefined8 *)(*pcVar4)();
          return puVar10;
        }
        puVar10 = (undefined8 *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
        puVar10[-1] = pvVar7;
      }
      *param_1 = puVar10;
      param_1[2] = uVar1;
      param_1[3] = uVar9;
      if (0xf < (ulonglong)param_3[3]) {
        param_3 = (undefined8 *)*param_3;
      }
      FUN_1400316b0(puVar10,param_3,uVar2);
      if (0xf < (ulonglong)param_4[3]) {
        param_4 = (undefined8 *)*param_4;
      }
      FUN_1400316b0((undefined8 *)((longlong)puVar10 + uVar2),param_4,uVar3 + 1);
    }
    else {
      uVar5 = param_4[1];
      *param_1 = *param_4;
      param_1[1] = uVar5;
      uVar5 = param_4[3];
      param_1[2] = param_4[2];
      param_1[3] = uVar5;
      param_4[2] = 0;
      param_4[3] = 0xf;
      *(undefined1 *)param_4 = 0;
      puVar10 = (undefined8 *)*param_1;
      FUN_1400316b0((undefined8 *)((longlong)puVar10 + uVar2),puVar10,uVar3 + 1);
      if (0xf < (ulonglong)param_3[3]) {
        param_3 = (undefined8 *)*param_3;
      }
      FUN_1400316b0(puVar10,param_3,uVar2);
      param_1[2] = uVar1;
    }
  }
  else {
    uVar5 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar5;
    uVar5 = param_3[3];
    param_1[2] = param_3[2];
    param_1[3] = uVar5;
    param_3[2] = 0;
    param_3[3] = 0xf;
    *(undefined1 *)param_3 = 0;
    puVar10 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      puVar10 = (undefined8 *)*param_1;
    }
    if (0xf < (ulonglong)param_4[3]) {
      param_4 = (undefined8 *)*param_4;
    }
    FUN_1400316b0((undefined8 *)((longlong)puVar10 + uVar2),param_4,uVar3 + 1);
    param_1[2] = uVar1;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025b00 @ 140025b00