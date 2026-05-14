undefined4 __thiscall
FUN_100045f0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  if (*(undefined4 **)((int)this + 8) != (undefined4 *)0x0) {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 8))(param_1,param_2,param_3,param_4);
    return uVar1;
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004630 @ 10004630