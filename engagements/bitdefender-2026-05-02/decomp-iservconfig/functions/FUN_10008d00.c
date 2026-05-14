int * __thiscall FUN_10008d00(void *this,uint param_1,char param_2)

{
  uint uVar1;
  uint uVar2;
  code *pcVar3;
  uint uVar4;
  void *pvVar5;
  void *pvVar6;
  int *piVar7;
  void *pvVar8;
  uint uVar9;
  
  uVar2 = *(uint *)((int)this + 0x14);
  if (param_1 <= uVar2) {
    pvVar8 = this;
    if (0xf < uVar2) {
                    /* WARNING: Load size is inaccurate */
      pvVar8 = *this;
    }
    *(uint *)((int)this + 0x10) = param_1;
    _memset(pvVar8,(int)param_2,param_1);
    *(undefined1 *)(param_1 + (int)pvVar8) = 0;
    return (int *)this;
  }
  if (param_1 < 0x80000000) {
    uVar9 = param_1 | 0xf;
    if ((uVar9 < 0x80000000) && (uVar2 <= 0x7fffffff - (uVar2 >> 1))) {
      uVar1 = (uVar2 >> 1) + uVar2;
      if (uVar9 < uVar1) {
        uVar9 = uVar1;
      }
      uVar1 = uVar9 + 1;
      if (0xfff < uVar1) {
        uVar4 = uVar9 + 0x24;
        if (uVar4 <= uVar1) goto LAB_10008e2b;
        goto LAB_10008d99;
      }
      if (uVar1 == 0) {
        pvVar8 = (void *)0x0;
      }
      else {
        pvVar8 = operator_new(uVar1);
      }
LAB_10008dc4:
      *(uint *)((int)this + 0x10) = param_1;
      *(uint *)((int)this + 0x14) = uVar9;
      _memset(pvVar8,(int)param_2,param_1);
      *(undefined1 *)((int)pvVar8 + param_1) = 0;
      if (uVar2 < 0x10) {
LAB_10008e14:
        *(void **)this = pvVar8;
        return (int *)this;
      }
                    /* WARNING: Load size is inaccurate */
      pvVar5 = *this;
      pvVar6 = pvVar5;
      if ((uVar2 + 1 < 0x1000) ||
         (pvVar6 = *(void **)((int)pvVar5 + -4), (uint)((int)pvVar5 + (-4 - (int)pvVar6)) < 0x20)) {
        FUN_1002e346(pvVar6);
        goto LAB_10008e14;
      }
    }
    else {
      uVar9 = 0x7fffffff;
      uVar4 = 0x80000023;
LAB_10008d99:
      pvVar5 = operator_new(uVar4);
      if (pvVar5 != (void *)0x0) {
        pvVar8 = (void *)((int)pvVar5 + 0x23U & 0xffffffe0);
        *(void **)((int)pvVar8 - 4) = pvVar5;
        goto LAB_10008dc4;
      }
    }
    FUN_10032f7f();
  }
  FUN_10001eb0();
LAB_10008e2b:
  FUN_10001fb0();
  pcVar3 = (code *)swi(3);
  piVar7 = (int *)(*pcVar3)();
  return piVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008e40 @ 10008e40