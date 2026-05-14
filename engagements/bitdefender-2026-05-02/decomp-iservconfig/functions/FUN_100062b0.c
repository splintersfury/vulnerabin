uint * __thiscall
FUN_100062b0(void *this,uint param_1,undefined4 param_2,uint *param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  code *pcVar4;
  void *pvVar5;
  undefined1 *puVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  uint *puVar10;
  
  uVar1 = *(uint *)((int)this + 0x10);
  if (0x7fffffff - uVar1 < param_1) {
    FUN_10001eb0();
LAB_10006403:
    FUN_10001fb0();
  }
  else {
    uVar2 = *(uint *)((int)this + 0x14);
    uVar8 = uVar1 + param_1 | 0xf;
    if (uVar8 < 0x80000000) {
      if (0x7fffffff - (uVar2 >> 1) < uVar2) {
        uVar8 = 0x7fffffff;
      }
      else {
        uVar7 = (uVar2 >> 1) + uVar2;
        if (uVar8 < uVar7) {
          uVar8 = uVar7;
        }
      }
    }
    else {
      uVar8 = 0x7fffffff;
    }
    uVar7 = -(uint)(0xfffffffe < uVar8) | uVar8 + 1;
    if (uVar7 < 0x1000) {
      if (uVar7 == 0) {
        puVar10 = (uint *)0x0;
      }
      else {
        puVar10 = (uint *)operator_new(uVar7);
      }
    }
    else {
      if (uVar7 + 0x23 <= uVar7) goto LAB_10006403;
      pvVar5 = operator_new(uVar7 + 0x23);
      if (pvVar5 == (void *)0x0) goto LAB_10006408;
      puVar10 = (uint *)((int)pvVar5 + 0x23U & 0xffffffe0);
      puVar10[-1] = (uint)pvVar5;
    }
    *(uint *)((int)this + 0x10) = uVar1 + param_1;
    *(uint *)((int)this + 0x14) = uVar8;
    puVar6 = (undefined1 *)(param_4 + (int)((int)puVar10 + uVar1));
    if (uVar2 < 0x10) {
      FUN_100301d0(puVar10,(uint *)this,uVar1);
      FUN_100301d0((uint *)((int)puVar10 + uVar1),param_3,param_4);
      *puVar6 = 0;
      *(uint **)this = puVar10;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar3 = *this;
    FUN_100301d0(puVar10,puVar3,uVar1);
    FUN_100301d0((uint *)(uVar1 + (int)puVar10),param_3,param_4);
    *puVar6 = 0;
    puVar9 = puVar3;
    if ((uVar2 + 1 < 0x1000) ||
       (puVar9 = (uint *)puVar3[-1], (uint)((int)puVar3 + (-4 - (int)puVar9)) < 0x20)) {
      FUN_1002e346(puVar9);
      *(uint **)this = puVar10;
      return (uint *)this;
    }
  }
LAB_10006408:
  FUN_10032f7f();
  pcVar4 = (code *)swi(3);
  puVar10 = (uint *)(*pcVar4)();
  return puVar10;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006410 @ 10006410