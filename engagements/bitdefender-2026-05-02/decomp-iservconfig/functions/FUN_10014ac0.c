uint * __thiscall FUN_10014ac0(void *this,undefined4 param_1,undefined4 param_2,undefined1 param_3)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  code *pcVar4;
  void *pvVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  
  uVar1 = *(uint *)((int)this + 0x10);
  if (uVar1 == 0x7fffffff) {
    FUN_10001eb0();
LAB_10014bee:
    FUN_10001fb0();
  }
  else {
    uVar2 = *(uint *)((int)this + 0x14);
    uVar8 = uVar1 + 1 | 0xf;
    if (uVar8 < 0x80000000) {
      if (0x7fffffff - (uVar2 >> 1) < uVar2) {
        uVar8 = 0x7fffffff;
      }
      else {
        uVar6 = (uVar2 >> 1) + uVar2;
        if (uVar8 < uVar6) {
          uVar8 = uVar6;
        }
      }
    }
    else {
      uVar8 = 0x7fffffff;
    }
    uVar6 = -(uint)(0xfffffffe < uVar8) | uVar8 + 1;
    if (uVar6 < 0x1000) {
      if (uVar6 == 0) {
        puVar7 = (uint *)0x0;
      }
      else {
        puVar7 = (uint *)operator_new(uVar6);
      }
    }
    else {
      if (uVar6 + 0x23 <= uVar6) goto LAB_10014bee;
      pvVar5 = operator_new(uVar6 + 0x23);
      if (pvVar5 == (void *)0x0) goto LAB_10014bf3;
      puVar7 = (uint *)((int)pvVar5 + 0x23U & 0xffffffe0);
      puVar7[-1] = (uint)pvVar5;
    }
    *(uint *)((int)this + 0x10) = uVar1 + 1;
    *(uint *)((int)this + 0x14) = uVar8;
    if (uVar2 < 0x10) {
      FUN_100301d0(puVar7,(uint *)this,uVar1);
      *(undefined1 *)((int)puVar7 + uVar1) = param_3;
      *(undefined1 *)((int)puVar7 + uVar1 + 1) = 0;
      *(uint **)this = puVar7;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar3 = *this;
    FUN_100301d0(puVar7,puVar3,uVar1);
    *(undefined1 *)((int)puVar7 + uVar1) = param_3;
    *(undefined1 *)((int)puVar7 + uVar1 + 1) = 0;
    puVar9 = puVar3;
    if ((uVar2 + 1 < 0x1000) ||
       (puVar9 = (uint *)puVar3[-1], (uint)((int)puVar3 + (-4 - (int)puVar9)) < 0x20)) {
      FUN_1002e346(puVar9);
      *(uint **)this = puVar7;
      return (uint *)this;
    }
  }
LAB_10014bf3:
  FUN_10032f7f();
  pcVar4 = (code *)swi(3);
  puVar7 = (uint *)(*pcVar4)();
  return puVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014c00 @ 10014c00