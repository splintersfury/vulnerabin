float * FUN_140016ed0(float *param_1,float *param_2)

{
  float *pfVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  void *pvVar4;
  longlong local_18 [2];
  
  *param_1 = *param_2;
  param_1[2] = 0.0;
  param_1[3] = 0.0;
  param_1[4] = 0.0;
  param_1[5] = 0.0;
  pvVar4 = operator_new(0x20);
  *(void **)pvVar4 = pvVar4;
  *(void **)((longlong)pvVar4 + 8) = pvVar4;
  *(void **)(param_1 + 2) = pvVar4;
  pfVar1 = param_1 + 6;
  pfVar1[0] = 0.0;
  pfVar1[1] = 0.0;
  param_1[8] = 0.0;
  param_1[9] = 0.0;
  param_1[10] = 0.0;
  param_1[0xb] = 0.0;
  *(undefined8 *)(param_1 + 0xc) = *(undefined8 *)(param_2 + 0xc);
  *(undefined8 *)(param_1 + 0xe) = *(undefined8 *)(param_2 + 0xe);
  FUN_140016fb0((ulonglong *)pfVar1,*(longlong *)(param_2 + 8) - *(longlong *)(param_2 + 6) >> 3,
                *(undefined8 *)(param_1 + 2));
  puVar2 = *(undefined8 **)(param_2 + 2);
  for (puVar3 = (undefined8 *)*puVar2; puVar3 != puVar2; puVar3 = (undefined8 *)*puVar3) {
    FUN_140017180(param_1,local_18,(byte *)(puVar3 + 2));
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140016f80 @ 140016f80