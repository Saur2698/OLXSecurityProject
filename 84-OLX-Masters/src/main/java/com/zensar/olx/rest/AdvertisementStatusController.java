package com.zensar.olx.rest;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.zensar.olx.bean.AdvertisementStatus;
import com.zensar.olx.bean.Category;
import com.zensar.olx.service.AdvertisementStatusService;
import com.zensar.olx.service.CategoryService;

@RestController
public class AdvertisementStatusController {
	
	@Autowired
	AdvertisementStatusService service;
	
	@PostMapping("/advertise/addStatus")
	public AdvertisementStatus addAdvertisementStatus(@RequestBody AdvertisementStatus advertisementStatus) {
		return this.service.addAdvertisementStatus(advertisementStatus);
	}
	
	@GetMapping("/advertise/getAllStatus")
	
	public List<AdvertisementStatus> getAllAdvertisementStatus(){
		System.out.println(this.service.getAllStatus());
		return this.service.getAllStatus();
		
	}
	
	@GetMapping("/advertise/status/{id}")
	public AdvertisementStatus findAdvertisementStatusById(@PathVariable(name = "id")int id) {
		return this.service.findAdvertisementStatus(id);
	}

}