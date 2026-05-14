uint * __thiscall FUN_100142f0(void *this,uint *param_1)

{
  uint *puVar1;
  uint *puVar2;
  int local_64 [7];
  uint local_48 [6];
  undefined1 local_30 [24];
  undefined4 local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004edfe;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  local_8 = 0;
                    /* WARNING: Load size is inaccurate */
  local_18 = 1;
  if (*this == '\x03') {
    puVar2 = *(uint **)((int)this + 8);
    if (param_1 != puVar2) {
      puVar1 = puVar2 + 4;
      if (0xf < puVar2[5]) {
        puVar2 = (uint *)*puVar2;
      }
      FUN_10008e70(param_1,puVar2,*puVar1);
    }
    ExceptionList = local_10;
    return param_1;
  }
  puVar2 = (uint *)FUN_1000f7b0((undefined1 *)this);
  puVar2 = FUN_10005690(local_30,puVar2);
  local_8 = 1;
  puVar2 = FUN_10005f20(local_48,(uint *)"type must be string, but is ",puVar2);
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_1000ad90(local_64,0x12e,puVar2);
                    /* WARNING: Subroutine does not return */
  __CxxThrowException_8(local_64,&DAT_10067608);
}


// FUNCTION_END

// FUNCTION_START: FUN_100143d0 @ 100143d0