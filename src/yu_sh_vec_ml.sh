L=10
while [ $L -lt 50 ]
do
	./yu_vec_ml_x $(echo $L) 80;
	L=$((L+10))
done
