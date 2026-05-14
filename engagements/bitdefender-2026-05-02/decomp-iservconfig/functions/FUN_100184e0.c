undefined4 * __thiscall FUN_100184e0(void *this,undefined4 *param_1)

{
  *param_1 = this;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0x80000000;
                    /* WARNING: Load size is inaccurate */
  if ((*this != '\x01') && (*this != '\x02')) {
    param_1[3] = 0x80000000;
  }
                    /* WARNING: Load size is inaccurate */
  if (*this != '\x01') {
    if (*this != '\x02') {
      param_1[3] = 1;
      return param_1;
    }
    param_1[2] = *(undefined4 *)(*(int *)((int)this + 8) + 4);
    return param_1;
  }
  param_1[1] = **(undefined4 **)((int)this + 8);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018550 @ 10018550