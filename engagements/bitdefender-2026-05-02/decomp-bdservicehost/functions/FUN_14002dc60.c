void FUN_14002dc60(void)

{
  _Lockit local_res8 [32];
  
  std::_Lockit::_Lockit(local_res8,0);
  _Deletegloballocale(&DAT_14007be18);
  DAT_14007be18 = 0;
  std::_Lockit::~_Lockit(local_res8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14002dc94 @ 14002dc94