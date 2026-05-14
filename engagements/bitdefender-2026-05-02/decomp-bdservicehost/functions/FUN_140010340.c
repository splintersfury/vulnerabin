longlong * FUN_140010340(longlong *param_1,undefined8 *param_2,ulonglong param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  void *pvVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  undefined8 *puVar8;
  
  uVar2 = param_1[3];
  if (uVar2 < param_3) {
    if (0x7ffffffffffffffe < param_3) {
      FUN_140001a20();
      pcVar3 = (code *)swi(3);
      plVar5 = (longlong *)(*pcVar3)();
      return plVar5;
    }
    uVar6 = param_3 | 7;
    uVar7 = 0x7ffffffffffffffe;
    if (((uVar6 < 0x7fffffffffffffff) && (uVar2 <= 0x7ffffffffffffffe - (uVar2 >> 1))) &&
       (uVar1 = (uVar2 >> 1) + uVar2, uVar7 = uVar6, uVar6 < uVar1)) {
      uVar7 = uVar1;
    }
    uVar6 = uVar7 + 1;
    if (uVar7 == 0xffffffffffffffff) {
      uVar6 = 0xffffffffffffffff;
    }
    if (0x7fffffffffffffff < uVar6) {
LAB_1400104ab:
      FUN_140001670();
      pcVar3 = (code *)swi(3);
      plVar5 = (longlong *)(*pcVar3)();
      return plVar5;
    }
    uVar6 = uVar6 * 2;
    puVar8 = (undefined8 *)0x0;
    if (uVar6 < 0x1000) {
      if (uVar6 != 0) {
        puVar8 = (undefined8 *)operator_new(uVar6);
      }
    }
    else {
      if (uVar6 + 0x27 <= uVar6) goto LAB_1400104ab;
      pvVar4 = operator_new(uVar6 + 0x27);
      if (pvVar4 == (void *)0x0) goto LAB_1400104a5;
      puVar8 = (undefined8 *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
      puVar8[-1] = pvVar4;
    }
    param_1[3] = uVar7;
    param_1[2] = param_3;
    FUN_1400316b0(puVar8,param_2,param_3 * 2);
    *(undefined2 *)(param_3 * 2 + (longlong)puVar8) = 0;
    if (7 < uVar2) {
      if ((0xfff < uVar2 * 2 + 2) && (0x1f < (*param_1 - *(longlong *)(*param_1 + -8)) - 8U)) {
LAB_1400104a5:
        FUN_140035d28();
        pcVar3 = (code *)swi(3);
        plVar5 = (longlong *)(*pcVar3)();
        return plVar5;
      }
      FUN_14002f180();
    }
    *param_1 = (longlong)puVar8;
  }
  else {
    plVar5 = param_1;
    if (7 < uVar2) {
      plVar5 = (longlong *)*param_1;
    }
    param_1[2] = param_3;
    FUN_1400316b0(plVar5,param_2,param_3 * 2);
    *(undefined2 *)(param_3 * 2 + (longlong)plVar5) = 0;
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: _Become_small @ 1400104c0

/* Library Function - Single Match
    public: void __cdecl std::basic_string<char,struct std::char_traits<char>,class
   std::allocator<char> >::_Become_small(void) __ptr64
   
   Library: Visual Studio 2017 Release */

void __thiscall
std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Become_small
          (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this)

{
  undefined8 *puVar1;
  code *pcVar2;
  
  puVar1 = *(undefined8 **)this;
  FUN_1400316b0((undefined8 *)this,puVar1,*(longlong *)(this + 0x10) + 1);
  if ((0xfff < *(longlong *)(this + 0x18) + 1U) &&
     (0x1f < (ulonglong)((longlong)puVar1 + (-8 - puVar1[-1])))) {
    FUN_140035d28();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  FUN_14002f180();
  *(undefined8 *)(this + 0x18) = 0xf;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010530 @ 140010530

undefined1 (*) [16] FUN_140010530(undefined1 (*param_1) [16],ulonglong param_2,byte param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  void *pvVar4;
  ulonglong uVar5;
  __uint64 _Var6;
  undefined1 (*pauVar7) [16];
  ulonglong uVar8;
  
  uVar2 = *(ulonglong *)(param_1[1] + 8);
  if (param_2 <= uVar2) {
    pauVar7 = param_1;
    if (0xf < uVar2) {
      pauVar7 = *(undefined1 (**) [16])*param_1;
    }
    *(ulonglong *)param_1[1] = param_2;
    FUN_140031e00(pauVar7,param_3,param_2);
    (*pauVar7)[param_2] = 0;
    return param_1;
  }
  if (0x7fffffffffffffff < param_2) {
    FUN_140001a20();
    pcVar3 = (code *)swi(3);
    pauVar7 = (undefined1 (*) [16])(*pcVar3)();
    return pauVar7;
  }
  uVar5 = param_2 | 0xf;
  uVar8 = 0x7fffffffffffffff;
  if (((uVar5 < 0x8000000000000000) && (uVar2 <= 0x7fffffffffffffff - (uVar2 >> 1))) &&
     (uVar1 = (uVar2 >> 1) + uVar2, uVar8 = uVar5, uVar5 < uVar1)) {
    uVar8 = uVar1;
  }
  _Var6 = uVar8 + 1;
  if (uVar8 == 0xffffffffffffffff) {
    _Var6 = 0xffffffffffffffff;
  }
  if (_Var6 < 0x1000) {
    if (_Var6 == 0) {
      pauVar7 = (undefined1 (*) [16])0x0;
    }
    else {
      pauVar7 = (undefined1 (*) [16])operator_new(_Var6);
    }
  }
  else {
    if (_Var6 + 0x27 <= _Var6) {
      FUN_140001670();
      pcVar3 = (code *)swi(3);
      pauVar7 = (undefined1 (*) [16])(*pcVar3)();
      return pauVar7;
    }
    pvVar4 = operator_new(_Var6 + 0x27);
    if (pvVar4 == (void *)0x0) goto LAB_140010687;
    pauVar7 = (undefined1 (*) [16])((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
    *(void **)(pauVar7[-1] + 8) = pvVar4;
  }
  *(ulonglong *)param_1[1] = param_2;
  *(ulonglong *)(param_1[1] + 8) = uVar8;
  FUN_140031e00(pauVar7,param_3,param_2);
  (*pauVar7)[param_2] = 0;
  if (0xf < uVar2) {
    if ((0xfff < uVar2 + 1) &&
       (0x1f < (*(longlong *)*param_1 - *(longlong *)(*(longlong *)*param_1 + -8)) - 8U)) {
LAB_140010687:
      FUN_140035d28();
      pcVar3 = (code *)swi(3);
      pauVar7 = (undefined1 (*) [16])(*pcVar3)();
      return pauVar7;
    }
    FUN_14002f180();
  }
  *(undefined1 (**) [16])*param_1 = pauVar7;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400106a0 @ 1400106a0