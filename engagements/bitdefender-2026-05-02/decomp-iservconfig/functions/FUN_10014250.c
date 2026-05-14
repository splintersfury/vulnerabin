uint * __fastcall FUN_10014250(uint *param_1,void *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  puVar4 = FUN_100055a0(param_2,param_3);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  uVar1 = puVar4[1];
  uVar2 = puVar4[2];
  uVar3 = puVar4[3];
  *param_1 = *puVar4;
  param_1[1] = uVar1;
  param_1[2] = uVar2;
  param_1[3] = uVar3;
  *(undefined8 *)(param_1 + 4) = *(undefined8 *)(puVar4 + 4);
  puVar4[4] = 0;
  puVar4[5] = 0xf;
  *(undefined1 *)puVar4 = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100142a0 @ 100142a0