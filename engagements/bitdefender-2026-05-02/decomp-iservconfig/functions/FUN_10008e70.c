uint * __thiscall FUN_10008e70(void *this,uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  code *pcVar3;
  uint uVar4;
  void *pvVar5;
  uint *puVar6;
  void *pvVar7;
  uint uVar8;
  
  uVar2 = *(uint *)((int)this + 0x14);
  if (param_2 <= uVar2) {
    puVar6 = (uint *)this;
    if (0xf < uVar2) {
                    /* WARNING: Load size is inaccurate */
      puVar6 = *this;
    }
    *(uint *)((int)this + 0x10) = param_2;
    FUN_100301d0(puVar6,param_1,param_2);
    *(undefined1 *)(param_2 + (int)puVar6) = 0;
    return (uint *)this;
  }
  if (param_2 < 0x80000000) {
    uVar8 = param_2 | 0xf;
    if ((uVar8 < 0x80000000) && (uVar2 <= 0x7fffffff - (uVar2 >> 1))) {
      uVar1 = (uVar2 >> 1) + uVar2;
      if (uVar8 < uVar1) {
        uVar8 = uVar1;
      }
      uVar1 = uVar8 + 1;
      if (0xfff < uVar1) {
        uVar4 = uVar8 + 0x24;
        if (uVar4 <= uVar1) goto LAB_10008f96;
        goto LAB_10008f06;
      }
      if (uVar1 == 0) {
        puVar6 = (uint *)0x0;
      }
      else {
        puVar6 = (uint *)operator_new(uVar1);
      }
LAB_10008f31:
      *(uint *)((int)this + 0x10) = param_2;
      *(uint *)((int)this + 0x14) = uVar8;
      FUN_100301d0(puVar6,param_1,param_2);
      *(undefined1 *)(param_2 + (int)puVar6) = 0;
      if (uVar2 < 0x10) {
LAB_10008f7f:
        *(uint **)this = puVar6;
        return (uint *)this;
      }
                    /* WARNING: Load size is inaccurate */
      pvVar5 = *this;
      pvVar7 = pvVar5;
      if ((uVar2 + 1 < 0x1000) ||
         (pvVar7 = *(void **)((int)pvVar5 + -4), (uint)((int)pvVar5 + (-4 - (int)pvVar7)) < 0x20)) {
        FUN_1002e346(pvVar7);
        goto LAB_10008f7f;
      }
    }
    else {
      uVar8 = 0x7fffffff;
      uVar4 = 0x80000023;
LAB_10008f06:
      pvVar5 = operator_new(uVar4);
      if (pvVar5 != (void *)0x0) {
        puVar6 = (uint *)((int)pvVar5 + 0x23U & 0xffffffe0);
        puVar6[-1] = (uint)pvVar5;
        goto LAB_10008f31;
      }
    }
    FUN_10032f7f();
  }
  FUN_10001eb0();
LAB_10008f96:
  FUN_10001fb0();
  pcVar3 = (code *)swi(3);
  puVar6 = (uint *)(*pcVar3)();
  return puVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008fa0 @ 10008fa0