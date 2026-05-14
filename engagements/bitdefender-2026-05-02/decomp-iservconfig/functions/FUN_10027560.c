void __thiscall FUN_10027560(void *this,uint param_1)

{
  code *pcVar1;
  uint uVar2;
  void *pvVar3;
  void *pvVar4;
  int iVar5;
  uint uVar6;
  uint *puVar7;
  
  if (param_1 < 0x80000000) {
                    /* WARNING: Load size is inaccurate */
    iVar5 = *(int *)((int)this + 4) - *this;
                    /* WARNING: Load size is inaccurate */
    uVar6 = *(int *)((int)this + 8) - *this;
    if (0x7fffffff - (uVar6 >> 1) < uVar6) {
      uVar6 = 0x7fffffff;
      uVar2 = 0x80000022;
LAB_100275a3:
      pvVar3 = operator_new(uVar2);
      if (pvVar3 != (void *)0x0) {
        puVar7 = (uint *)((int)pvVar3 + 0x23U & 0xffffffe0);
        puVar7[-1] = (uint)pvVar3;
        goto LAB_100275f1;
      }
    }
    else {
      uVar6 = (uVar6 >> 1) + uVar6;
      if (uVar6 < param_1) {
        uVar6 = param_1;
      }
      if (0xfff < uVar6) {
        uVar2 = uVar6 + 0x23;
        if (uVar2 <= uVar6) goto LAB_10027669;
        goto LAB_100275a3;
      }
      if (uVar6 == 0) {
        puVar7 = (uint *)0x0;
      }
      else {
        puVar7 = (uint *)operator_new(uVar6);
      }
LAB_100275f1:
      _memset((void *)((int)puVar7 + iVar5),0,param_1 - iVar5);
                    /* WARNING: Load size is inaccurate */
      FUN_100301d0(puVar7,*this,*(int *)((int)this + 4) - (int)*this);
                    /* WARNING: Load size is inaccurate */
      pvVar3 = *this;
      if (pvVar3 == (void *)0x0) {
LAB_10027646:
        *(uint **)this = puVar7;
        *(uint *)((int)this + 4) = param_1 + (int)puVar7;
        *(uint *)((int)this + 8) = (int)puVar7 + uVar6;
        return;
      }
      pvVar4 = pvVar3;
      if (((uint)(*(int *)((int)this + 8) - (int)pvVar3) < 0x1000) ||
         (pvVar4 = *(void **)((int)pvVar3 + -4), (uint)((int)pvVar3 + (-4 - (int)pvVar4)) < 0x20)) {
        FUN_1002e346(pvVar4);
        goto LAB_10027646;
      }
    }
    FUN_10032f7f();
  }
  FUN_10017fa0();
LAB_10027669:
  FUN_10001fb0();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027670 @ 10027670