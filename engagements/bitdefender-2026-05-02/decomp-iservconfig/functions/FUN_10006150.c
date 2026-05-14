uint * __thiscall
FUN_10006150(void *this,uint param_1,undefined4 param_2,size_t param_3,char param_4)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  code *pcVar4;
  void *pvVar5;
  uint uVar6;
  uint uVar7;
  uint *puVar8;
  uint *puVar9;
  
  uVar1 = *(uint *)((int)this + 0x10);
  if (0x7fffffff - uVar1 < param_1) {
    FUN_10001eb0();
LAB_100062a4:
    FUN_10001fb0();
  }
  else {
    uVar2 = *(uint *)((int)this + 0x14);
    uVar7 = uVar1 + param_1 | 0xf;
    if (uVar7 < 0x80000000) {
      if (0x7fffffff - (uVar2 >> 1) < uVar2) {
        uVar7 = 0x7fffffff;
      }
      else {
        uVar6 = (uVar2 >> 1) + uVar2;
        if (uVar7 < uVar6) {
          uVar7 = uVar6;
        }
      }
    }
    else {
      uVar7 = 0x7fffffff;
    }
    uVar6 = -(uint)(0xfffffffe < uVar7) | uVar7 + 1;
    if (uVar6 < 0x1000) {
      if (uVar6 == 0) {
        puVar9 = (uint *)0x0;
      }
      else {
        puVar9 = (uint *)operator_new(uVar6);
      }
    }
    else {
      if (uVar6 + 0x23 <= uVar6) goto LAB_100062a4;
      pvVar5 = operator_new(uVar6 + 0x23);
      if (pvVar5 == (void *)0x0) goto LAB_100062a9;
      puVar9 = (uint *)((int)pvVar5 + 0x23U & 0xffffffe0);
      puVar9[-1] = (uint)pvVar5;
    }
    *(uint *)((int)this + 0x10) = uVar1 + param_1;
    *(uint *)((int)this + 0x14) = uVar7;
    pvVar5 = (void *)((int)puVar9 + uVar1);
    if (uVar2 < 0x10) {
      FUN_100301d0(puVar9,(uint *)this,uVar1);
      _memset(pvVar5,(int)param_4,param_3);
      *(undefined1 *)(param_3 + (int)pvVar5) = 0;
      *(uint **)this = puVar9;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar3 = *this;
    FUN_100301d0(puVar9,puVar3,uVar1);
    _memset(pvVar5,(int)param_4,param_3);
    *(undefined1 *)(param_3 + (int)pvVar5) = 0;
    puVar8 = puVar3;
    if ((uVar2 + 1 < 0x1000) ||
       (puVar8 = (uint *)puVar3[-1], (uint)((int)puVar3 + (-4 - (int)puVar8)) < 0x20)) {
      FUN_1002e346(puVar8);
      *(uint **)this = puVar9;
      return (uint *)this;
    }
  }
LAB_100062a9:
  FUN_10032f7f();
  pcVar4 = (code *)swi(3);
  puVar9 = (uint *)(*pcVar4)();
  return puVar9;
}


// FUNCTION_END

// FUNCTION_START: FUN_100062b0 @ 100062b0