#!/bin/bash

input="01 78 45 6D 61 69 6C 20 53 69 67 6E 61 74 75 72 65"
output="{"

# Split the input string into an array based on space
IFS=" " read -ra segments <<< "$input"

# Iterate through the segments
for segment in "${segments[@]}"; do
	#Convert the segment to uppercase
	segment_upper=$(echo "$segment" | tr 'a-f' 'A-F')

	# Append the formatted segment to the output
	output+="(byte) 0x$segment_upper, "
done

# Remove the trailing comma and space
output="${output%, }"

output+="};"

echo "$output"
