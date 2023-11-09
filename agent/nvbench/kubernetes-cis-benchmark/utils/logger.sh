#!/bin/bash

info () {

  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldblu}[INFO]${txtrst}${level_info}${s_txt}${scoring_info} $1"
}

pass () {

  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldgrn}[PASS]${txtrst}${level_info}${s_txt}${scoring_info} $1"

}

warn () {
  s_txt=""
  if echo "$1" | grep -q "(Automated)"; then
    s_txt="${bldcyn}[Automated]${txtrst}"
  elif echo "$1" | grep -q "(Manual)"; then
    s_txt="${bldcyn}[Manual]${txtrst}"
  fi

  level_info=""
  scoring_info=""
  if [ ${#s_txt} -ne 0 ]; then
    idx=$(echo "$1" | cut -d " " -f 1)
    if echo "$level2" | grep -q "\<${idx}\>"; then
      level_info="${bldgry}[Level 2]${txtrst}"
    else
      level_info="${bldgry}[Level 1]${txtrst}"
    fi
    if echo "$not_scored" | grep -q "\<${idx}\>"; then
      scoring_info="${bldgry}[Not Scored]${txtrst}"
    else
      scoring_info="${bldgry}[Scored]${txtrst}"
    fi
  fi

  printf "%b\n" "${bldred}[WARN]${txtrst}${level_info}${s_txt}${scoring_info} $1"

}

yell () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}