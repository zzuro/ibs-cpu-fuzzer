total=$(find /mnt/ssd/ibs_log -maxdepth 1 -mindepth 1 ! -name 'fuzz_state*' | wc -l)
count=0

for f in /mnt/ssd/ibs_log/*; do
  # Skip files starting with fuzz_state
  case "$(basename "$f")" in
    fuzz_state*) continue ;;
  esac

  count=$((count+1))
  printf "\r[%d/%d] %s" "$count" "$total" "$f"

  if ! mv "$f" /mnt/truenas/ibs_log/ 2>/dev/null; then
    rm -f "$f"
  fi
done

echo
echo "Done."