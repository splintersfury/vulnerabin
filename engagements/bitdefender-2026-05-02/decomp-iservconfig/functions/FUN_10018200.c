undefined4 __thiscall FUN_10018200(void *this,int *param_1)

{
  char cVar1;
  int local_48 [7];
  uint local_2c [7];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f30d;
  local_10 = ExceptionList;
                    /* WARNING: Load size is inaccurate */
  if (*this != (char *)*param_1) {
    ExceptionList = &local_10;
    FUN_10005690(local_2c,(uint *)"cannot compare iterators of different containers");
    local_8 = 0;
    FUN_1000abb0(local_48,0xd4,local_2c);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_48,&DAT_1006750c);
  }
  cVar1 = **this;
  if (cVar1 != '\x01') {
    if (cVar1 != '\x02') {
      return CONCAT31((int3)((uint)*(int *)((int)this + 0xc) >> 8),
                      *(int *)((int)this + 0xc) != param_1[3]);
    }
    return CONCAT31((int3)((uint)*(int *)((int)this + 8) >> 8),*(int *)((int)this + 8) != param_1[2]
                   );
  }
  return CONCAT31((int3)((uint)*(int *)((int)this + 4) >> 8),*(int *)((int)this + 4) != param_1[1]);
}


// FUNCTION_END

// FUNCTION_START: FUN_100182c0 @ 100182c0