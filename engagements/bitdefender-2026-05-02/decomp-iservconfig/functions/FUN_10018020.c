uint * __thiscall FUN_10018020(void *this,undefined4 param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  code *pcVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  void *pvVar7;
  uint uVar8;
  uint *puVar9;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  uVar1 = param_2[4];
  uVar2 = param_3[4];
  uVar5 = uVar2 + uVar1;
  if ((uVar2 <= param_2[5] - uVar1) && (param_3[5] <= param_2[5])) {
    uVar6 = param_2[1];
    uVar8 = param_2[2];
    uVar4 = param_2[3];
    *(uint *)this = *param_2;
    *(uint *)((int)this + 4) = uVar6;
    *(uint *)((int)this + 8) = uVar8;
    *(uint *)((int)this + 0xc) = uVar4;
    *(undefined8 *)((int)this + 0x10) = *(undefined8 *)(param_2 + 4);
    param_2[4] = 0;
    param_2[5] = 0xf;
    *(undefined1 *)param_2 = 0;
    pvVar7 = this;
    if (0xf < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      pvVar7 = *this;
    }
    if (0xf < param_3[5]) {
      param_3 = (uint *)*param_3;
    }
    FUN_100301d0((uint *)((int)pvVar7 + uVar1),param_3,uVar2 + 1);
    *(uint *)((int)this + 0x10) = uVar5;
    return (uint *)this;
  }
  if (uVar1 <= param_3[5] - uVar2) {
    uVar6 = param_3[1];
    uVar8 = param_3[2];
    uVar4 = param_3[3];
    *(uint *)this = *param_3;
    *(uint *)((int)this + 4) = uVar6;
    *(uint *)((int)this + 8) = uVar8;
    *(uint *)((int)this + 0xc) = uVar4;
    *(undefined8 *)((int)this + 0x10) = *(undefined8 *)(param_3 + 4);
    param_3[4] = 0;
    param_3[5] = 0xf;
    *(undefined1 *)param_3 = 0;
                    /* WARNING: Load size is inaccurate */
    puVar9 = *this;
    FUN_100301d0((uint *)((int)puVar9 + uVar1),puVar9,uVar2 + 1);
    if (0xf < param_2[5]) {
      param_2 = (uint *)*param_2;
    }
    FUN_100301d0(puVar9,param_2,uVar1);
    *(uint *)((int)this + 0x10) = uVar5;
    return (uint *)this;
  }
  if (0x7fffffff - uVar1 < uVar2) {
    FUN_10001eb0();
  }
  else {
    uVar6 = uVar5 | 0xf;
    if (uVar6 < 0x80000000) {
      if (uVar6 < 0x16) {
        uVar6 = 0x16;
      }
    }
    else {
      uVar6 = 0x7fffffff;
    }
    uVar8 = -(uint)(0xfffffffe < uVar6) | uVar6 + 1;
    if (uVar8 < 0x1000) {
      if (uVar8 == 0) {
        puVar9 = (uint *)0x0;
      }
      else {
        puVar9 = (uint *)operator_new(uVar8);
      }
LAB_100181a7:
      *(uint *)((int)this + 0x10) = uVar5;
      *(uint **)this = puVar9;
      *(uint *)((int)this + 0x14) = uVar6;
      if (0xf < param_2[5]) {
        param_2 = (uint *)*param_2;
      }
      FUN_100301d0(puVar9,param_2,uVar1);
      if (0xf < param_3[5]) {
        param_3 = (uint *)*param_3;
      }
      FUN_100301d0((uint *)(uVar1 + (int)puVar9),param_3,uVar2 + 1);
      return (uint *)this;
    }
    if (uVar8 < uVar8 + 0x23) {
      pvVar7 = operator_new(uVar8 + 0x23);
      if (pvVar7 != (void *)0x0) {
        puVar9 = (uint *)((int)pvVar7 + 0x23U & 0xffffffe0);
        puVar9[-1] = (uint)pvVar7;
        goto LAB_100181a7;
      }
      goto LAB_100181fa;
    }
  }
  FUN_10001fb0();
LAB_100181fa:
  FUN_10032f7f();
  pcVar3 = (code *)swi(3);
  puVar9 = (uint *)(*pcVar3)();
  return puVar9;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018200 @ 10018200