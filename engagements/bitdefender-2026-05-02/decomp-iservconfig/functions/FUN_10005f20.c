uint * __fastcall FUN_10005f20(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *this;
  uint *puVar4;
  uint *local_8;
  
  this = param_3;
  puVar4 = param_2;
  do {
    uVar3 = *puVar4;
    puVar4 = (uint *)((int)puVar4 + 1);
  } while ((char)uVar3 != '\0');
  puVar4 = (uint *)((int)puVar4 - ((int)param_2 + 1));
  uVar3 = param_3[5];
  uVar1 = param_3[4];
  if ((uint *)(uVar3 - uVar1) < puVar4) {
    param_3 = (uint *)(uVar3 & 0xffffff00);
    this = FUN_100065e0(this,(uint)puVar4,param_3,uVar1,param_2,(uint)puVar4);
  }
  else {
    param_3[4] = uVar1 + (int)puVar4;
    local_8 = param_3;
    if (0xf < uVar3) {
      local_8 = (uint *)*param_3;
    }
    param_3 = puVar4;
    if ((local_8 < (uint *)((int)puVar4 + (int)param_2)) &&
       (param_2 <= (uint *)(uVar1 + (int)local_8))) {
      if (param_2 < local_8) {
        param_3 = (uint *)((int)local_8 - (int)param_2);
      }
      else {
        param_3 = (uint *)0x0;
      }
    }
    FUN_100301d0((uint *)((int)local_8 + (int)puVar4),local_8,uVar1 + 1);
    FUN_100301d0(local_8,param_2,(uint)param_3);
    FUN_100301d0((uint *)((int)local_8 + (int)param_3),
                 (uint *)((int)param_3 + (int)puVar4 + (int)param_2),(int)puVar4 - (int)param_3);
  }
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  uVar3 = this[1];
  uVar1 = this[2];
  uVar2 = this[3];
  *param_1 = *this;
  param_1[1] = uVar3;
  param_1[2] = uVar1;
  param_1[3] = uVar2;
  *(undefined8 *)(param_1 + 4) = *(undefined8 *)(this + 4);
  this[4] = 0;
  this[5] = 0xf;
  *(undefined1 *)this = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006030 @ 10006030